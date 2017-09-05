/******************************************************************************
 * v4v.c
 *
 * V4V (2nd cut of v2v)
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/compat.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/v4v.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>

//#undef V4V_DEBUG

#ifdef V4V_DEBUG
#define MY_FILE "v4v.c"
#define v4v_xfree(a) do { printk(KERN_ERR "%s:%d xfree(%p)\n",MY_FILE,__LINE__,(void *)a);  xfree(a); } while (1==0)
#define v4v_xmalloc(a) ({ void *ret; ret=xmalloc(a);  printk(KERN_ERR "%s:%d xmalloc(%s)=%p\n",MY_FILE,__LINE__, #a , ret); ret; })
#define v4v_xmalloc_array(a,b) ({ void *ret; ret=xmalloc_array(a,b);  printk(KERN_ERR "%s:%d xmalloc_array(%s,%d)=%p\n",MY_FILE,__LINE__, #a ,b, ret); ret; })
#else
#define v4v_xfree(a) xfree(a)
#define v4v_xmalloc(a) xmalloc(a)
#define v4v_xmalloc_array(a,b) xmalloc_array(a,b)
#endif


extern void send_guest_global_virq(struct domain *d, uint32_t virq);

DEFINE_XEN_GUEST_HANDLE (uint8_t);
static struct v4v_ring_info *v4v_ring_find_info (struct domain *d,
                                                 struct v4v_ring_id *id);

static struct v4v_ring_info *v4v_ring_find_info_by_addr (struct domain *d,
                                                         struct v4v_addr *a,
                                                         domid_t p);

/***** locks ****/
/* locking is organized as follows: */

/* the global lock v4v_lock: L1 protects the v4v elements */
/* of all struct domain *d in the system, it does not */
/* protect any of the elements of d->v4v, just their */
/* addresses. By extension since the destruction of */
/* a domain with a non-NULL d->v4v will need to free */
/* the d->v4v pointer, holding this lock gauruntees */
/* that no domains pointers in which v4v is interested */
/* become invalid whilst this lock is held. */

static DEFINE_RWLOCK (v4v_lock); /* L1 */

/* the lock d->v4v->lock: L2:  Read on protects the hash table and */
/* the elements in the hash_table d->v4v->ring_hash, and */
/* the node and id fields in struct v4v_ring_info in the */
/* hash table. Write on L2 protects all of the elements of */
/* struct v4v_ring_info. To take L2 you must already have R(L1) */
/* W(L1) implies W(L2) and L3 */

/* the lock v4v_ring_info *ringinfo; ringinfo->lock: L3: */
/* protects len,tx_ptr the guest ring, the */
/* guest ring_data and the pending list. To take L3 you must */
/* already have R(L2). W(L2) implies L3 */

struct list_head viprules = LIST_HEAD_INIT(viprules);

/*Debugs*/

#ifdef V4V_DEBUG
static void
v4v_hexdump (void *_p, int len)
{
  uint8_t *buf = (uint8_t *) _p;
  int i, j;

  for (i = 0; i < len; i += 16)
    {
      printk (KERN_ERR "%p:", &buf[i]);
      for (j = 0; j < 16; ++j)
        {
          int k = i + j;
          if (k < len)
            {
              printk (" %02x", buf[k]);
            }
          else
            {
              printk ("   ");
            }
        }
      printk (" ");

      for (j = 0; j < 16; ++j)
        {
          int k = i + j;
          if (k < len)
            {
              printk ("%c", ((buf[k] > 32) && (buf[k] < 127)) ? buf[k] : '.');
            }
          else
            {
              printk (" ");
            }
        }

      printk ("\n");
    }


}
#endif

/*********************** Event channel misery ****************/

static void
v4v_signal_domain (struct domain *d)
{
  send_guest_global_virq (d, VIRQ_V4V);
}

static void
v4v_signal_domid (domid_t id)
{
  struct domain *d = get_domain_by_id (id);
  if (!d)
    return;
  v4v_signal_domain (d);
  put_domain (d);
}


/******************* ring buffer ******************/

/*called must have L3*/
static void
v4v_ring_unmap (struct v4v_ring_info *ring_info)
{
  int i;
  for (i = 0; i < ring_info->npage; ++i)
    {
      if (!ring_info->mfn_mapping[i])
        continue;
#ifdef V4V_DEBUG
      printk (KERN_ERR "%s:%d unmapping page %p from %p\n",
              MY_FILE, __LINE__, (void *) mfn_x (ring_info->mfns[i]),
              ring_info->mfn_mapping[i]);
#endif
      unmap_domain_page (ring_info->mfn_mapping[i]);
      ring_info->mfn_mapping[i] = NULL;
    }
}

/*called must have L3*/
static uint8_t *
v4v_ring_map_page (struct v4v_ring_info *ring_info, int i)
{
  if (i >= ring_info->npage)
    return NULL;
  if (ring_info->mfn_mapping[i])
    return ring_info->mfn_mapping[i];
  ring_info->mfn_mapping[i] = map_domain_page (mfn_x (ring_info->mfns[i]));
#ifdef V4V_DEBUG
  printk (KERN_ERR "%s:%d mapping page %p to %p\n",
          MY_FILE, __LINE__, (void *) mfn_x (ring_info->mfns[i]),
          ring_info->mfn_mapping[i]);
#endif
  return ring_info->mfn_mapping[i];
}

/*called must have L3*/
static int
v4v_memcpy_from_guest_ring (void *_dst, struct v4v_ring_info *ring_info,
                            uint32_t offset, uint32_t len)
{
  int page = offset >> PAGE_SHIFT;
  uint8_t *src;
  uint8_t *dst = _dst;


  offset &= PAGE_SIZE - 1;

  while ((offset + len) > PAGE_SIZE)
    {
      src = v4v_ring_map_page (ring_info, page);

      if (!src)
          return -EFAULT;

#ifdef V4V_DEBUG
      printk (KERN_ERR "%s:%d memcpy(%p,%p+%d,%d)\n",
              MY_FILE, __LINE__, dst, src, offset,
              (int) (PAGE_SIZE - offset));
#endif
      memcpy (dst, src + offset, PAGE_SIZE - offset);


      page++;
      len -= PAGE_SIZE - offset;
      dst += PAGE_SIZE - offset;
      offset = 0;
    }

  src = v4v_ring_map_page (ring_info, page);
  if (!src)
      return -EFAULT;

#ifdef V4V_DEBUG
  printk (KERN_ERR "%s:%d memcpy(%p,%p+%d,%d)\n",
          MY_FILE, __LINE__, dst, src, offset, len);
#endif
  memcpy (dst, src + offset, len);

  return 0;
}


/*called must have L3*/
static int
v4v_update_tx_ptr (struct v4v_ring_info *ring_info, uint32_t tx_ptr)
{
    uint8_t *dst = v4v_ring_map_page (ring_info, 0);
    volatile uint32_t *p = (uint32_t *)(dst + offsetof (v4v_ring_t, tx_ptr));
    if (!dst)
        return -EFAULT;
    *p = tx_ptr;
    return 0;
}

/*called must have L3*/
static int
v4v_memcpy_to_guest_ring (struct v4v_ring_info *ring_info, uint32_t offset,
                          void *_src, uint32_t len)
{
  int page = offset >> PAGE_SHIFT;
  uint8_t *dst;
  uint8_t *src = _src;

  offset &= PAGE_SIZE - 1;

  while ((offset + len) > PAGE_SIZE)
    {
      dst = v4v_ring_map_page (ring_info, page);

      if (!dst)
          return -EFAULT;

#ifdef V4V_DEBUG
      printk (KERN_ERR "%s:%d memcpy(%p+%d,%p,%d)\n",
              MY_FILE, __LINE__, dst, offset, src,
              (int) (PAGE_SIZE - offset));
      v4v_hexdump (src, PAGE_SIZE - offset);
      v4v_hexdump (dst + offset, PAGE_SIZE - offset);
#endif
      memcpy (dst + offset, src, PAGE_SIZE - offset);

      page++;
      len -= (PAGE_SIZE - offset);
      src += (PAGE_SIZE - offset);
      offset = 0;
    }

  dst = v4v_ring_map_page (ring_info, page);

  if (!dst)
    {
      printk (KERN_ERR "attempted to map page %d of %d\n", page,
              ring_info->npage);
      return -EFAULT;
    }

#ifdef V4V_DEBUG
  printk (KERN_ERR "%s:%d memcpy(%p+%d,%p,%d)\n",
          MY_FILE, __LINE__, dst, offset, src, len);
  v4v_hexdump (src, len);
  v4v_hexdump (dst + offset, len);
#endif
  memcpy (dst + offset, src, len);

  return 0;
}



/*called must have L3*/
static int
v4v_memcpy_to_guest_ring_from_guest (struct v4v_ring_info *ring_info,
                                     uint32_t offset,
                                     XEN_GUEST_HANDLE (uint8_t) src_hnd,
                                     uint32_t len)
{
  int page = offset >> PAGE_SHIFT;
  uint8_t *dst;

  offset &= PAGE_SIZE - 1;

  while ((offset + len) > PAGE_SIZE)
    {
      dst = v4v_ring_map_page (ring_info, page);

      if (!dst)
          return -EFAULT;

#ifdef V4V_DEBUG
      printk (KERN_ERR "%s:%d copy_from_guest(%p+%d,%p,%d)\n",
              MY_FILE, __LINE__, dst, offset, (void *) src_hnd.p,
              (int) (PAGE_SIZE - offset));
#endif
      if (copy_from_guest ((dst + offset), src_hnd, PAGE_SIZE - offset))
          return -EFAULT;


      page++;
      len -= PAGE_SIZE - offset;
      guest_handle_add_offset (src_hnd, PAGE_SIZE - offset);
      offset = 0;
    }

  dst = v4v_ring_map_page (ring_info, page);

  if (!dst)
      return -EFAULT;

#ifdef V4V_DEBUG
  printk (KERN_ERR "%s:%d copy_from_guest(%p+%d,%p,%d)\n",
          MY_FILE, __LINE__, dst, offset, (void *) src_hnd.p, len);
#endif
  if (copy_from_guest ((dst + offset), src_hnd, len))
      return -EFAULT;

  return 0;
}

/*caller must have L3*/
#if 0
uint32_t
v4v_ringbuf_payload_space (struct domain * d,
                           struct v4v_ring_info * ring_info)
{
  XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd = ring_info->ring;
  v4v_ring_t ring;
  int32_t ret;

  ring.tx_ptr = ring_info->tx_ptr;
  ring.len = ring_info->len;

  if (copy_field_from_guest (&ring, ring_hnd, rx_ptr))
    return 0;

  if (ring.rx_ptr == ring.tx_ptr)
    return ring.len - sizeof (struct v4v_ring_message_header);

  ret = ring.rx_ptr - ring.tx_ptr;
  if (ret < 0)
    ret += ring.len;

  ret -= sizeof (struct v4v_ring_message_header);

  return (ret < 0) ? 0 : ret;
}
#else

static int
v4v_ringbuf_get_rx_ptr (struct domain *d, struct v4v_ring_info *ring_info,
                        uint32_t * rx_ptr)
{
  v4v_ring_t *ringp;

  if (ring_info->npage == 0)
    return -1;

  ringp = map_domain_page (mfn_x (ring_info->mfns[0]));
#ifdef V4V_DEBUG
  printk (KERN_ERR "v4v_ringbuf_payload_space: mapped %p to %p\n",
          (void *) mfn_x (ring_info->mfns[0]), ringp);
#endif
  if (!ringp)
    return -1;

  *rx_ptr = *(volatile uint32_t *) &ringp->rx_ptr;

  unmap_domain_page ((void*)ringp);


  return 0;
}



uint32_t
v4v_ringbuf_payload_space (struct domain * d,
                           struct v4v_ring_info * ring_info)
{
  v4v_ring_t ring;
  int32_t ret;

  ring.tx_ptr = ring_info->tx_ptr;
  ring.len = ring_info->len;


  if (v4v_ringbuf_get_rx_ptr (d, ring_info, &ring.rx_ptr))
    return 0;

#ifdef V4V_DEBUG
  printk (KERN_ERR "v4v_ringbuf_payload_space:tx_ptr=%d rx_ptr=%d\n",
          (int) ring.tx_ptr, (int) ring.rx_ptr);
#endif

  if (ring.rx_ptr == ring.tx_ptr)
    return ring.len - sizeof (struct v4v_ring_message_header);

  ret = ring.rx_ptr - ring.tx_ptr;
  if (ret < 0)
    ret += ring.len;

  ret -= sizeof (struct v4v_ring_message_header);
  ret -= V4V_ROUNDUP (1);

  return (ret < 0) ? 0 : ret;
}
#endif

/*
 * v4v_sanitize_ring creates a modified copy of the ring pointers
 * where the rx_ptr is rounded up to ensure it is aligned, and then
 * ring wrap is handled. Simplifies safe use of the rx_ptr for
 * available space calculation.
 */
static void v4v_sanitize_ring(v4v_ring_t *ring,
                              struct v4v_ring_info *ring_info)
{
  uint32_t rx_ptr = ring->rx_ptr;

  ring->tx_ptr = ring_info->tx_ptr;
  ring->len = ring_info->len;

  rx_ptr = V4V_ROUNDUP(rx_ptr);
  if (rx_ptr >= ring_info->len)
    rx_ptr = 0;

  ring->rx_ptr = rx_ptr;
}


/*caller must have L3*/
static long
v4v_ringbuf_insert (struct domain *d,
                    struct v4v_ring_info *ring_info,
                    struct v4v_ring_id *src_id, uint32_t proto,
                    XEN_GUEST_HANDLE (void) buf_hnd_void, uint32_t len)
{
  XEN_GUEST_HANDLE (uint8_t) buf_hnd =
    guest_handle_cast (buf_hnd_void, uint8_t);
  v4v_ring_t ring;
  struct v4v_ring_message_header mh = { 0 };
  int32_t sp;
  int32_t happy_ret = len;
  int32_t ret = 0;

  if (((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >=
      ring_info->len) ||
      (len > V4V_MAX_MSG_SIZE))
      return -ENOBUFS;

  do
    {

      if ((ret =
           v4v_memcpy_from_guest_ring (&ring, ring_info, 0, sizeof (ring))))
        break;

      v4v_sanitize_ring(&ring, ring_info);

#ifdef V4V_DEBUG
      printk (KERN_ERR
              "ring.tx_ptr=%d ring.rx_ptr=%d ring.len=%d ring_info->tx_ptr=%d\n",
              ring.tx_ptr, ring.rx_ptr, ring.len, ring_info->tx_ptr);
#endif


      if (ring.rx_ptr == ring.tx_ptr)
        {
          sp = ring_info->len;
        }
      else
        {
          sp = ring.rx_ptr - ring.tx_ptr;
          if (sp < 0)
            sp += ring.len;
        }

      if ((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >= sp)
        {
          ret = -EAGAIN;
          break;
        }

      mh.len = len + sizeof (struct v4v_ring_message_header);
      mh.source = src_id->addr;
      mh.pad = 0;
      mh.protocol = proto;


      if ((ret =
           v4v_memcpy_to_guest_ring (ring_info,
                                     ring.tx_ptr + sizeof (v4v_ring_t), &mh,
                                     sizeof (mh))))
        break;

      ring.tx_ptr += sizeof (mh);
      if (ring.tx_ptr == ring_info->len)
        ring.tx_ptr = 0;

      sp = ring.len - ring.tx_ptr;

      if (len > sp)
        {
          if ((ret =
               v4v_memcpy_to_guest_ring_from_guest (ring_info,
                                                    ring.tx_ptr +
                                                    sizeof (v4v_ring_t),
                                                    buf_hnd, sp)))
            break;

          ring.tx_ptr = 0;
          len -= sp;
          guest_handle_add_offset (buf_hnd, sp);
        }

      if ((ret =
           v4v_memcpy_to_guest_ring_from_guest (ring_info,
                                                ring.tx_ptr +
                                                sizeof (v4v_ring_t), buf_hnd,
                                                len)))
        break;

      ring.tx_ptr += V4V_ROUNDUP (len);

      if (ring.tx_ptr == ring_info->len)
        ring.tx_ptr = 0;

      mb ();
      ring_info->tx_ptr = ring.tx_ptr;

      if ((ret = v4v_update_tx_ptr(ring_info, ring.tx_ptr)))
          break;

    }
  while (1 == 0);

  v4v_ring_unmap (ring_info);

  return ret ? ret : happy_ret;

}

static long
v4v_iov_count (XEN_GUEST_HANDLE (v4v_iov_t) iovs, int niov)
{
  v4v_iov_t iov;
  size_t ret = 0;

  if (niov > V4V_MAXIOV)
    return -EINVAL;

  while (niov--)
    {
      if (copy_from_guest (&iov, iovs, 1))
        return -EFAULT;

      ret += iov.iov_len;

      if (ret > V4V_MAX_MSG_SIZE)
        return -EINVAL;

      guest_handle_add_offset (iovs, 1);
    }

  return ret;

}

/*caller must have L3*/
static ssize_t
v4v_ringbuf_insertv (struct domain *d,
                     struct v4v_ring_info *ring_info,
                     struct v4v_ring_id *src_id, uint32_t proto,
                     XEN_GUEST_HANDLE (v4v_iov_t) iovs, uint32_t niov,
                     uint32_t len)
{
  v4v_ring_t ring;
  struct v4v_ring_message_header mh = { 0 };
  int32_t sp;
  int32_t happy_ret;
  int32_t ret = 0;
  uint32_t orig_len = len, total_len = 0;

  happy_ret = len;

  if (((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >=
      ring_info->len) ||
      (len > V4V_MAX_MSG_SIZE))
      return -ENOBUFS;

  if (niov > V4V_MAXIOV)
      return -EINVAL;

  do
    {

      if ((ret =
           v4v_memcpy_from_guest_ring (&ring, ring_info, 0, sizeof (ring))))
        break;

      v4v_sanitize_ring(&ring, ring_info);

#ifdef V4V_DEBUG
      printk (KERN_ERR
              "ring.tx_ptr=%d ring.rx_ptr=%d ring.len=%d ring_info->tx_ptr=%d\n",
              ring.tx_ptr, ring.rx_ptr, ring.len, ring_info->tx_ptr);
#endif


      if (ring.rx_ptr == ring.tx_ptr)
        {
          sp = ring_info->len;
        }
      else
        {
          sp = ring.rx_ptr - ring.tx_ptr;
          if (sp < 0)
            sp += ring.len;
        }

      if ((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >= sp)
        {
          ret = -EAGAIN;
          break;
        }

      mh.len = len + sizeof (struct v4v_ring_message_header);
      mh.source = src_id->addr;
      mh.pad = 0;
      mh.protocol = proto;


      if ((ret =
           v4v_memcpy_to_guest_ring (ring_info,
                                     ring.tx_ptr + sizeof (v4v_ring_t), &mh,
                                     sizeof (mh))))
        break;

      ring.tx_ptr += sizeof (mh);
      if (ring.tx_ptr == ring_info->len)
        ring.tx_ptr = 0;

      while (niov--)
        {
          XEN_GUEST_HANDLE_PARAM (uint8_t) bufp_hnd;
          XEN_GUEST_HANDLE (uint8_t) buf_hnd;
          v4v_iov_t iov;

          if (copy_from_guest (&iov, iovs, 1))
            {
              ret = -EFAULT;
              break;
            }

          bufp_hnd = guest_handle_from_ptr(iov.iov_base, uint8_t);
          buf_hnd = guest_handle_from_param(bufp_hnd, uint8_t);
          len = iov.iov_len;

          if (len > V4V_MAX_MSG_SIZE)
            {
              ret = -EINVAL;
              break;
            }

          total_len += len;
          if (total_len > orig_len)
            {
              ret = -EINVAL;
              break;
            }

          if (unlikely (!guest_handle_okay (buf_hnd, len)))
            {
              ret = -EFAULT;
              break;
            }

          sp = ring.len - ring.tx_ptr;

          if (len > sp)
            {
              if ((ret =
                   v4v_memcpy_to_guest_ring_from_guest (ring_info,
                                                        ring.tx_ptr +
                                                        sizeof (v4v_ring_t),
                                                        buf_hnd, sp)))
                break;

              ring.tx_ptr = 0;
              len -= sp;
              guest_handle_add_offset (buf_hnd, sp);
            }

          if ((ret =
               v4v_memcpy_to_guest_ring_from_guest (ring_info,
                                                    ring.tx_ptr +
                                                    sizeof (v4v_ring_t),
                                                    buf_hnd, len)))
            break;

          ring.tx_ptr += len;

          if (ring.tx_ptr == ring_info->len)
            ring.tx_ptr = 0;

          guest_handle_add_offset (iovs, 1);
        }
      if (ret)
        break;

      ring.tx_ptr = V4V_ROUNDUP (ring.tx_ptr);

      if (ring.tx_ptr >= ring_info->len)
        ring.tx_ptr -= ring_info->len;


      mb ();
      ring_info->tx_ptr = ring.tx_ptr;
      if ((ret = v4v_update_tx_ptr(ring_info, ring.tx_ptr)))
          break;
    }
  while (1 == 0);

  v4v_ring_unmap (ring_info);

  return ret ? ret : happy_ret;

}



/***** pending ******/

static void
v4v_pending_remove_ent (struct v4v_pending_ent *ent)
{
  hlist_del (&ent->node);
  v4v_xfree (ent);
}

/*caller must have L3 */
static void
v4v_pending_remove_all (struct v4v_ring_info *info)
{

  struct hlist_node *node, *next;
  struct v4v_pending_ent *pending_ent;


  hlist_for_each_entry_safe (pending_ent, node, next, &info->pending,
                             node) v4v_pending_remove_ent (pending_ent);
}

/*Caller must hold L1 */
static void
v4v_pending_notify (struct domain *caller_d, struct hlist_head *to_notify)
{
  struct hlist_node *node, *next;
  struct v4v_pending_ent *pending_ent;


  hlist_for_each_entry_safe (pending_ent, node, next, to_notify, node)
  {
    hlist_del (&pending_ent->node);
    v4v_signal_domid (pending_ent->id);
    v4v_xfree (pending_ent);
  }

}

/*caller must have R(L2) */
static void
v4v_pending_find (struct v4v_ring_info *ring_info, uint32_t payload_space,
                  struct hlist_head *to_notify)
{
  struct hlist_node *node, *next;
  struct v4v_pending_ent *ent;

  spin_lock (&ring_info->lock);
  hlist_for_each_entry_safe (ent, node, next, &ring_info->pending, node)
  {
    if (payload_space >= ent->len)
      {
        hlist_del (&ent->node);
        hlist_add_head (&ent->node, to_notify);
      }
  }
  spin_unlock (&ring_info->lock);
}

/*caller must have L3 */
static int
v4v_pending_queue (struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
  struct v4v_pending_ent *ent = v4v_xmalloc (struct v4v_pending_ent);
  if (!ent)
      return -ENOMEM;

  ent->len = len;
  ent->id = src_id;

  hlist_add_head (&ent->node, &ring_info->pending);

  return 0;
}

/* L3 */
static int
v4v_pending_requeue (struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
  struct hlist_node *node;
  struct v4v_pending_ent *ent;

  hlist_for_each_entry (ent, node, &ring_info->pending, node)
    if (ent->id == src_id)
    {
      if (ent->len < len)
        ent->len = len;
      return 0;
    }

  return v4v_pending_queue (ring_info, src_id, len);
}


/* L3 */
static void
v4v_pending_cancel (struct v4v_ring_info *ring_info, domid_t src_id)
{
  struct hlist_node *node, *next;
  struct v4v_pending_ent *ent;

  hlist_for_each_entry_safe (ent, node, next, &ring_info->pending, node)
  {
    if (ent->id == src_id)
      {
        hlist_del (&ent->node);
        v4v_xfree (ent);
      }
  }
}



/*ring data*/


/*Caller should hold R(L1)*/
static int
v4v_fill_ring_data (struct domain *src_d,
                    XEN_GUEST_HANDLE (v4v_ring_data_ent_t) data_ent_hnd)
{
  v4v_ring_data_ent_t ent;
  struct domain *dst_d;
  struct v4v_ring_info *ring_info;

  if (copy_from_guest (&ent, data_ent_hnd, 1))
      return -EFAULT;

#ifdef V4V_DEBUG
  printk (KERN_ERR
          "v4v_fill_ring_data: ent.ring.domain=%d,ent.ring.port=%d\n",
          (int) ent.ring.domain, (int) ent.ring.port);
#endif

  ent.flags = 0;

  dst_d = get_domain_by_id (ent.ring.domain);

  if (dst_d && dst_d->v4v)
    {
      read_lock (&dst_d->v4v->lock);
      ring_info =
        v4v_ring_find_info_by_addr (dst_d, &ent.ring, src_d->domain_id);

      if (ring_info)
        {
          uint32_t space_avail;

          ent.flags |= V4V_RING_DATA_F_EXISTS;
          ent.max_message_size =
            ring_info->len - sizeof (struct v4v_ring_message_header) -
            V4V_ROUNDUP (1);
          spin_lock (&ring_info->lock);

          space_avail = v4v_ringbuf_payload_space (dst_d, ring_info);


#if 0
          printk (KERN_ERR
                  "Xen_notify port=%d space_avail=%d space_wanted=%d\n",
                  (int) ring_info->id.addr.port, (int) space_avail,
                  (int) ent.space_required);
#endif


          if (space_avail >= ent.space_required)
            {
              v4v_pending_cancel (ring_info, src_d->domain_id);
              ent.flags |= V4V_RING_DATA_F_SUFFICIENT;
            }
          else
            {
              v4v_pending_requeue (ring_info, src_d->domain_id,
                                   ent.space_required);
              ent.flags |= V4V_RING_DATA_F_PENDING;
            }

          spin_unlock (&ring_info->lock);

          if (space_avail == ent.max_message_size)
            ent.flags |= V4V_RING_DATA_F_EMPTY;

        }
      read_unlock (&dst_d->v4v->lock);
    }

  if (dst_d)
    put_domain (dst_d);

  if (copy_field_to_guest (data_ent_hnd, &ent, flags))
      return -EFAULT;
#if 0                           //FIXME sa
  if (copy_field_to_guest (data_ent_hnd, &ent, space_avail))
    {
      DEBUG_BANANA;
      return -EFAULT;
    }

#ifdef V4V_DEBUG
  printk (KERN_ERR "    ent.flags=%04x ent.space_avail=%d\n",
          ent.flags, (int) ent.space_avail);
#endif
#endif

  return 0;
}

/*Called should hold no more than R(L1) */
static int
v4v_fill_ring_datas (struct domain *d, size_t nent,
                     XEN_GUEST_HANDLE (v4v_ring_data_ent_t) data_ent_hnd)
{
  int ret = 0;
  if (nent > V4V_MAXENT)
    return -EINVAL;
  read_lock (&v4v_lock);
  while (!ret && nent--)
    {
      ret = v4v_fill_ring_data (d, data_ent_hnd);
      guest_handle_add_offset (data_ent_hnd, 1);
    }
  read_unlock (&v4v_lock);
  return ret;
}

/**************************************** ring ************************/




static int
v4v_find_ring_mfns (struct domain *d, struct v4v_ring_info *ring_info,
                    XEN_GUEST_HANDLE (v4v_pfn_list_t) pfn_list_hnd)
{
  XEN_GUEST_HANDLE (v4v_pfn_t) pfn_hnd;
  v4v_pfn_list_t pfn_list;
  int i, j, ret = 0;
  mfn_t *mfns;
  uint8_t **mfn_mapping;
  unsigned long mfn;
  struct page_info *page;

  if (copy_from_guest (&pfn_list, pfn_list_hnd, 1))
      return -EFAULT;


  if (pfn_list.magic != V4V_PFN_LIST_MAGIC)
      return -EINVAL;

  /*
   * Julian:
   *
   * Check there's enough pages in the list to cover the entire ring.
   *
   */
  if ((pfn_list.npage << PAGE_SHIFT) < ring_info->len)
      return -EINVAL;

  {
    XEN_GUEST_HANDLE (uint8_t) slop_hnd =
      guest_handle_cast (pfn_list_hnd, uint8_t);
    guest_handle_add_offset (slop_hnd, sizeof (v4v_pfn_list_t));
    pfn_hnd = guest_handle_cast (slop_hnd, v4v_pfn_t);
  }

  if (pfn_list.npage  > (V4V_MAX_RING_SIZE >> PAGE_SHIFT))
      return -EINVAL;

  mfns = v4v_xmalloc_array (mfn_t, pfn_list.npage);
  if (!mfns)
      return -ENOMEM;

  mfn_mapping = v4v_xmalloc_array (uint8_t *, pfn_list.npage);
  if (!mfn_mapping)
    {
      v4v_xfree (mfns);
      return -ENOMEM;
    }


  for (i = 0; i < pfn_list.npage; ++i)
    {
      v4v_pfn_t pfn;
      if (copy_from_guest_offset (&pfn, pfn_hnd, i, 1))
        {
          ret = -EFAULT;
          break;
        }
      page = get_page_from_gfn (d, pfn, NULL, P2M_ALLOC);
      if (unlikely(!page)) {
          printk(KERN_ERR "v4v domain %d passed invalid gmfn %"PRI_mfn" ring %p seq %d\n",
                 d->domain_id, pfn, ring_info, i);
          ret = -EINVAL;
          break;
      }
      mfn = page_to_mfn (page);
      if ( !mfn_valid(mfn) )
        {
          printk(KERN_ERR "v4v domain %d passed invalid mfn %"PRI_mfn" ring %p seq %d\n",
                 d->domain_id, mfn, ring_info, i);
          ret = -EINVAL;
          put_page(page);
          break;
        }
      if ( !get_page_type(page, PGT_writable_page) )
        {
          printk(KERN_ERR "v4v domain %d passed wrong type mfn %"PRI_mfn" ring %p seq %d\n",
          d->domain_id, mfn, ring_info, i);
          ret = -EINVAL;
          put_page(page);
          break;
        }
      mfns[i] = _mfn(mfn);

#ifdef V4V_DEBUG
      printk (KERN_ERR "v4v_find_ring_mfns: %d: %lx -> %lx\n",
              i, (unsigned long) pfn, (unsigned long) mfn_x (mfns[i]));
#endif
      if (mfn_x (mfns[i]) == INVALID_MFN)
        {
          v4v_xfree (mfn_mapping);
          v4v_xfree (mfns);
          return -EINVAL;
        }
      mfn_mapping[i] = NULL;
    }

  if (!ret)
    {
      ring_info->npage = pfn_list.npage;
      ring_info->mfns = mfns;
      ring_info->mfn_mapping = mfn_mapping;
    }
  else
    {
      j = i;
      for (i=0; i < j; ++i)
        if (mfn_x(mfns[i]) != 0)
          put_page_and_type(mfn_to_page(mfn_x(mfns[i])));
        v4v_xfree (mfn_mapping);
        v4v_xfree (mfns);
    }
  return ret;
}


/* caller must hold R(L2) */
static struct v4v_ring_info *
v4v_ring_find_info (struct domain *d, struct v4v_ring_id *id)
{
  uint16_t hash;
  struct hlist_node *node;
  struct v4v_ring_info *ring_info;

  hash = v4v_hash_fn (id);

#ifdef V4V_DEBUG
  printk (KERN_ERR
          "ring_find_info: d->v4v=%p, d->v4v->ring_hash[%d]=%p id=%p\n",
          d->v4v, (int) hash, d->v4v->ring_hash[hash].first, id);
  printk (KERN_ERR
          "ring_find_info: id.addr.port=%d id.addr.domain=%d id.addr.partner=%d\n",
          id->addr.port, id->addr.domain, id->partner);
#endif

  hlist_for_each_entry (ring_info, node, &d->v4v->ring_hash[hash], node)
  {
    if (!memcmp (id, &ring_info->id, sizeof (*id)))
      {
#ifdef V4V_DEBUG
        printk (KERN_ERR "ring_find_info: ring_info=%p\n", ring_info);

#endif
        return ring_info;
      }
  }
#ifdef V4V_DEBUG
  printk (KERN_ERR "ring_find_info: no ring_info found\n");
#endif

  return NULL;
}

/* caller must hold R(L2) */
static struct v4v_ring_info *
v4v_ring_find_info_by_addr (struct domain *d, struct v4v_addr *a, domid_t p)
{
  struct v4v_ring_id id;
  struct v4v_ring_info *ret;

  if (!a)
    return NULL;

  id.addr.port = a->port;
  id.addr.domain = d->domain_id;
  id.partner = p;

  ret = v4v_ring_find_info (d, &id);
  if (ret)
    return ret;

  id.partner = V4V_DOMID_NONE;

  return v4v_ring_find_info (d, &id);
}

/*caller must hold W(L2) */
static void v4v_ring_remove_mfns (struct v4v_ring_info *ring_info)
{
    int i;
    if (ring_info->mfns) {
        for (i=0; i < ring_info->npage; ++i)
            if (mfn_x(ring_info->mfns[i]) != 0)
                put_page_and_type(mfn_to_page(mfn_x(ring_info->mfns[i])));
        v4v_xfree (ring_info->mfns);
    }
    ring_info->mfns = NULL;
}

/*caller must hold W(L2) */
static void
v4v_ring_remove_info (struct v4v_ring_info *ring_info)
{
    v4v_pending_remove_all (ring_info);

    hlist_del (&ring_info->node);
    v4v_ring_remove_mfns(ring_info);
    v4v_xfree (ring_info);
}

/* Call from guest to unpublish a ring */
static long
v4v_ring_remove (struct domain *d, XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd)
{
  struct v4v_ring ring;
  struct v4v_ring_info *ring_info;
  int ret = 0;

  read_lock (&v4v_lock);

  do
    {

      if (!d->v4v)
        {
          ret = -EINVAL;
          break;
        }

      if (copy_from_guest (&ring, ring_hnd, 1))
        {
          ret = -EFAULT;
          break;
        }

      if (ring.magic != V4V_RING_MAGIC)
        {
          ret = -EINVAL;
          break;
        }

      ring.id.addr.domain = d->domain_id;

      write_lock (&d->v4v->lock);
      ring_info = v4v_ring_find_info (d, &ring.id);

      if (ring_info)
        v4v_ring_remove_info (ring_info);

      write_unlock (&d->v4v->lock);

      if (!ring_info)
        {
          ret = -ENOENT;
          break;
        }

    }
  while (1 == 0);

  read_unlock (&v4v_lock);

  return ret;
}

/* call from guest to publish a ring */
static long
v4v_ring_add (struct domain *d, XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd,
              XEN_GUEST_HANDLE (v4v_pfn_list_t) pfn_list_hnd)
{
  struct v4v_ring ring;
//  struct v4v_ring_data ring_data = { 0 };
  struct v4v_ring_info *ring_info;
  int need_to_insert = 0;
  int ret = 0;

  if ((long) ring_hnd.p & (PAGE_SIZE - 1))
      return -EINVAL;

  read_lock (&v4v_lock);

  do
    {
      if (!d->v4v)
        {
          ret = -EINVAL;
          break;
        }

      if (copy_from_guest (&ring, ring_hnd, 1))
        {
          ret = -EFAULT;
          break;
        }

      if (ring.magic != V4V_RING_MAGIC)
        {
          ret = -EINVAL;
          break;
        }

      if ((ring.len <
           (sizeof (struct v4v_ring_message_header) + V4V_ROUNDUP (1) +
            V4V_ROUNDUP (1))) || (V4V_ROUNDUP (ring.len) != ring.len))
        {
          ret = -EINVAL;
          break;
        }

      if (ring.len > V4V_MAX_RING_SIZE)
        {
          ret = -EINVAL;
          break;
        }

      ring.id.addr.domain = d->domain_id;
      if (copy_field_to_guest (ring_hnd, &ring, id))
        {
          ret = -EFAULT;
          break;
        }

      /* no need for a lock yet, because only we know about this */
      /* set the tx pointer if it looks bogus (we don't reset it because this might be a re-register after S4) */
      if ((ring.tx_ptr >= ring.len)
          || (V4V_ROUNDUP (ring.tx_ptr) != ring.tx_ptr))
        {
          /*
           * Since the ring is a mess, attempt to flush the contents of it
           * here by setting the tx_ptr to the next aligned message slot past
           * the latest rx_ptr we have observed. Handle ring wrap correctly.
           */
          ring.tx_ptr = V4V_ROUNDUP(ring.rx_ptr);
          if (ring.tx_ptr >= ring.len)
          {
            ring.tx_ptr = 0;
          }
          copy_field_to_guest (ring_hnd, &ring, tx_ptr); /* XXX: not atomic */
        }

#if 0
      if (ring_data_hnd)
        {
          /* Quick sanity check on ring_data_hnd */
          if (copy_from_guest (&magic, ring_data_hnd, 1))
            {
              ret = -EFAULT;
              break;
            }

          if (magic != V4V_RING_DATA_MAGIC)
            {
              ret = -EINVAL;
              break;
            }

          if (copy_from_guest (&ring_data, ring_data_hnd, 1))
            {
              ret = -EFAULT;
              break;
            }
        }
#endif


      write_lock (&d->v4v->lock);
      ring_info = v4v_ring_find_info (d, &ring.id);

      if (!ring_info)
        {
          ring_info = v4v_xmalloc (struct v4v_ring_info);
          if (!ring_info)
            {
              ret = -ENOMEM;
              write_unlock (&d->v4v->lock);
              break;
            }
          need_to_insert++;
          spin_lock_init (&ring_info->lock);
          INIT_HLIST_HEAD (&ring_info->pending);
          ring_info->mfns = NULL;

        } else {
          /* Ring info already existed. If mfn list was already populated remove the
           * MFN's from list and then add the new list.
           */
          printk(KERN_INFO "v4v: dom%d re-registering existing ring, clearing MFN list\n",
              current->domain->domain_id);
          v4v_ring_remove_mfns(ring_info);
      }

      /* Since we hold W(L2), no need to take L3 here */
      ring_info->id = ring.id;
      ring_info->len = ring.len;
      ring_info->tx_ptr = ring.tx_ptr;
      ring_info->ring = ring_hnd;
      if (ring_info->mfns)
        xfree (ring_info->mfns);
      ret = v4v_find_ring_mfns (d, ring_info, pfn_list_hnd);
      if (ret)
        {
          write_unlock (&d->v4v->lock);
          break;
        }
      if (need_to_insert)
        {
          uint16_t hash = v4v_hash_fn (&ring.id);
          hlist_add_head (&ring_info->node, &d->v4v->ring_hash[hash]);
        }
      write_unlock (&d->v4v->lock);
    }
  while (1 == 0);

  read_unlock (&v4v_lock);
  return ret;
}

/**************************** VIPTables ***************************/

static void
v4v_viptables_print_rule (struct v4v_viptables_rule_node *rule)
{
  if (rule == NULL)
    {
      printk("(null)\n");
      return;
    }

  if (rule->accept == 1)
    printk("ACCEPT");
  else
    printk("REJECT");

  printk(" ");

  if (rule->src.domain == DOMID_INVALID)
    printk("*");
  else
    printk("%i", rule->src.domain);

  printk(":");

  if (rule->src.port == -1)
    printk("*");
  else
    printk("%u", rule->src.port);

  printk(" -> ");

  if (rule->dst.domain == DOMID_INVALID)
    printk("*");
  else
    printk("%i", rule->dst.domain);

  printk(":");

  if (rule->dst.port == -1)
    printk("*");
  else
    printk("%u", rule->dst.port);

  printk("\n");
}

static int
v4v_viptables_add (struct domain *src_d, XEN_GUEST_HANDLE(v4v_viptables_rule_t) rule,
                   int32_t position)
{
  struct v4v_viptables_rule_node* new;
  struct list_head* tmp;

  /* First rule is n.1 */
  position--;

  new = v4v_xmalloc (struct v4v_viptables_rule_node);

  if (copy_field_from_guest (new, rule, src))
    return -EFAULT;
  if (copy_field_from_guest (new, rule, dst))
    return -EFAULT;
  if (copy_field_from_guest (new, rule, accept))
    return -EFAULT;

  printk(KERN_ERR "VIPTables: ");
  v4v_viptables_print_rule(new);

  tmp = &viprules;
  while (position != 0 && tmp->next != &viprules)
    {
      tmp = tmp->next;
      position--;
    }
  list_add(&new->list, tmp);

  return 0;
}

static int
v4v_viptables_del (struct domain *src_d, XEN_GUEST_HANDLE(v4v_viptables_rule_t) rule,
                   int32_t position)
{
  struct list_head *tmp = NULL;
  struct list_head *next = NULL;
  struct v4v_viptables_rule_node *node;
  struct v4v_viptables_rule *r;

  if (position != -1)
    {
      /* We want to delete the rule number <position> */
      tmp = &viprules;
      while (position != 0 && tmp->next != &viprules)
        {
          tmp = tmp->next;
          position--;
        }
    }
  else if (!guest_handle_is_null(rule))
    {
      /* We want to delete the rule <rule> */
      r = v4v_xmalloc (struct v4v_viptables_rule);

      if (copy_field_from_guest (r, rule, src))
        return -EFAULT;
      if (copy_field_from_guest (r, rule, dst))
        return -EFAULT;
      if (copy_field_from_guest (r, rule, accept))
        return -EFAULT;

      list_for_each(tmp, &viprules)
        {
          node = list_entry(tmp, struct v4v_viptables_rule_node, list);

          if ((node->src.domain == r->src.domain) &&
              (node->src.port   == r->src.port)   &&
              (node->dst.domain == r->dst.domain) &&
              (node->dst.port   == r->dst.port))
            {
              position = 0;
              break;
            }
        }
      v4v_xfree(r);
    }
  else
    {
      /* We want to flush the rules! */
      printk(KERN_ERR "VIPTables: flushing rules\n");
      list_for_each_safe(tmp, next, &viprules)
        {
          node = list_entry(tmp, struct v4v_viptables_rule_node, list);
          list_del(tmp);
          v4v_xfree(node);
        }
    }

  if (position == 0 && tmp != &viprules)
    {
      printk(KERN_ERR "VIPTables: deleting rule: ");
      node = list_entry(tmp, struct v4v_viptables_rule_node, list);
      v4v_viptables_print_rule(node);
      list_del(tmp);
      v4v_xfree(node);
    }

  return 0;
}

static int
v4v_viptables_list (struct domain *src_d, XEN_GUEST_HANDLE(v4v_viptables_list_t) list_hnd)
{
  struct list_head *ptr;
  struct v4v_viptables_rule_node *node;
  struct v4v_viptables_list rules_list;

  memset(&rules_list, 0, sizeof (rules_list));
  if (copy_field_from_guest (&rules_list, list_hnd, nb_rules))
      return -EFAULT;

  ptr = viprules.next;
  while (rules_list.nb_rules != 0 && ptr != &viprules)
  {
      ptr = ptr->next;
      rules_list.nb_rules--;
  }

  if (rules_list.nb_rules != 0)
      return -EFAULT;

  while (rules_list.nb_rules < V4V_VIPTABLES_LIST_SIZE &&
         ptr != &viprules)
  {
      node = list_entry(ptr, struct v4v_viptables_rule_node, list);

      rules_list.rules[rules_list.nb_rules].src = node->src;
      rules_list.rules[rules_list.nb_rules].dst = node->dst;
      rules_list.rules[rules_list.nb_rules].accept = node->accept;

      rules_list.nb_rules++;
      ptr = ptr->next;
  }

  if (copy_to_guest(list_hnd, &rules_list, 1))
      return -EFAULT;

  return 0;
}

static size_t
v4v_viptables_check (v4v_addr_t * src, v4v_addr_t * dst)
{
  struct list_head *ptr;
  struct v4v_viptables_rule_node *node;

  list_for_each(ptr, &viprules)
    {
      node = list_entry(ptr, struct v4v_viptables_rule_node, list);

      if ((node->src.domain == DOMID_INVALID || node->src.domain == src->domain) &&
          (node->src.port   == -1            || node->src.port   == src->port)   &&
          (node->dst.domain == DOMID_INVALID || node->dst.domain == dst->domain) &&
          (node->dst.port   == -1            || node->dst.port   == dst->port))
        return !node->accept;
    }

  /* Defaulting to ACCEPT */
  return 0;
}

/**************************** io ***************************/

/*Caller must hold v4v_lock and hash_lock*/
static void
v4v_notify_ring (struct domain *d, struct v4v_ring_info *ring_info,
                 struct hlist_head *to_notify)
{
  uint32_t space;

  spin_lock (&ring_info->lock);
  space = v4v_ringbuf_payload_space (d, ring_info);
  spin_unlock (&ring_info->lock);

  v4v_pending_find (ring_info, space, to_notify);

}

/*notify hypercall*/
static long
v4v_notify (struct domain *d,
            XEN_GUEST_HANDLE (v4v_ring_data_t) ring_data_hnd)
{
  v4v_ring_data_t ring_data;
  HLIST_HEAD (to_notify);
  int i;
  int ret = 0;

  read_lock (&v4v_lock);

  if (!d->v4v)
    {
      read_unlock (&v4v_lock);
      return -ENODEV;
    }

  read_lock (&d->v4v->lock);
  for (i = 0; i < V4V_HTABLE_SIZE; ++i)
    {
      struct hlist_node *node, *next;
      struct v4v_ring_info *ring_info;

      hlist_for_each_entry_safe (ring_info, node,
                                 next, &d->v4v->ring_hash[i],
                                 node)
        v4v_notify_ring (d, ring_info, &to_notify);
    }
  read_unlock (&d->v4v->lock);



  if (!hlist_empty (&to_notify))
    {
      v4v_pending_notify (d, &to_notify);
    }

  do
    {
      if (!guest_handle_is_null (ring_data_hnd))
        {
          /* Quick sanity check on ring_data_hnd */
          if (copy_field_from_guest (&ring_data, ring_data_hnd, magic))
            {
              ret = -EFAULT;
              break;
            }

          if (ring_data.magic != V4V_RING_DATA_MAGIC)
            {
              ret = -EINVAL;
              break;
            }

          if (copy_from_guest (&ring_data, ring_data_hnd, 1))
            {
              ret = -EFAULT;
              break;
            }


          {
            XEN_GUEST_HANDLE (v4v_ring_data_ent_t) ring_data_ent_hnd;
            XEN_GUEST_HANDLE (uint8_t) slop_hnd =
              guest_handle_cast (ring_data_hnd, uint8_t);
            guest_handle_add_offset (slop_hnd, sizeof (v4v_ring_data_t));
            ring_data_ent_hnd =
              guest_handle_cast (slop_hnd, v4v_ring_data_ent_t);
            ret = v4v_fill_ring_datas (d, ring_data.nent, ring_data_ent_hnd);

          }
        }
    }
  while (1 == 0);

  read_unlock (&v4v_lock);

  return ret;
}



/*Hypercall to do the send*/
static long
v4v_send (struct domain *src_d, v4v_addr_t * src_addr,
          v4v_addr_t * dst_addr, uint32_t proto,
          XEN_GUEST_HANDLE (void) buf, size_t len)
{
  struct domain *dst_d;
  struct v4v_ring_id src_id;
  struct v4v_ring_info *ring_info;
  long ret = 0;

  if (!dst_addr)
      return -EINVAL;

  if (len > V4V_MAX_MSG_SIZE)
      return -EINVAL;

  read_lock (&v4v_lock);
  if (!src_d->v4v)
    {
      read_unlock (&v4v_lock);
      return -EINVAL;
    }

#if 0
  read_lock (&src_d->v4v->lock);
  ring_info = v4v_ring_find_info_by_addr (src_d, src_addr, dst_addr->domain);
  if (ring_info)
    {
      src_id = ring_info->id;
    }
  else
    {
      src_id.addr.port = V4V_PORT_NONE;
      src_id.addr.partner = dst_addr->domain;
    }
  read_unlock (&src_d->v4v->lock);
#endif

  src_id.addr.port = src_addr->port;
  src_id.addr.domain = src_d->domain_id;
  src_id.partner = dst_addr->domain;

  dst_d = get_domain_by_id (dst_addr->domain);
  if (!dst_d)
    {
      read_unlock (&v4v_lock);
      return -ENOTCONN;
    }

  /* XSM: verify if src is allowed to send to dst */
  if (xsm_v4v_send(XSM_HOOK, src_d, dst_d) != 0)
    {
      printk(KERN_ERR "V4V: XSM REJECTED %i -> %i\n",
             src_addr->domain, dst_addr->domain);
      ret = -EPERM;
      goto out;
    }
  /* VIPTables*/
  if (v4v_viptables_check(src_addr, dst_addr) != 0)
    {
      printk(KERN_ERR "V4V: VIPTables REJECTED %i:%u -> %i:%u\n",
             src_addr->domain, src_addr->port,
             dst_addr->domain, dst_addr->port);
      ret = -ENOTCONN;
      goto out;
    }

  do
    {

      if (!dst_d->v4v)
        {
          ret = -ENOTCONN;
          break;
        }

      read_lock (&dst_d->v4v->lock);
      ring_info =
        v4v_ring_find_info_by_addr (dst_d, dst_addr, src_addr->domain);

      if (!ring_info)
          ret = -ENOTCONN;
      else
        {
          spin_lock (&ring_info->lock);
          ret =
            v4v_ringbuf_insert (dst_d, ring_info, &src_id, proto, buf, len);
          if (ret == -EAGAIN)
            {
              /* Schedule a wake up on the event channel when space is there */
              if (v4v_pending_requeue (ring_info, src_d->domain_id, len))
                  ret = -ENOMEM;
            }
          spin_unlock (&ring_info->lock);

          if (ret >= 0)
            {
              v4v_signal_domain (dst_d);
            }

        }
      read_unlock (&dst_d->v4v->lock);

    }
  while (1 == 0);

out:
  put_domain (dst_d);
  read_unlock (&v4v_lock);
  return ret;
}

/*Hypercall to do the send*/
static long
v4v_sendv (struct domain *src_d, v4v_addr_t * src_addr,
           v4v_addr_t * dst_addr, uint32_t proto,
           XEN_GUEST_HANDLE (v4v_iov_t) iovs, size_t niov)
{
  struct domain *dst_d;
  struct v4v_ring_id src_id;
  struct v4v_ring_info *ring_info;
  int ret = 0;


  if (!dst_addr)
      return -EINVAL;

  read_lock (&v4v_lock);
  if (!src_d->v4v)
    {
      read_unlock (&v4v_lock);
      return -EINVAL;
    }

#if 0
  read_lock (&src_d->v4v->lock);
  ring_info = v4v_ring_find_info_by_addr (src_d, src_addr, dst_addr->domain);
  if (ring_info)
    {
      src_id = ring_info->id;
    }
  else
    {
      src_id.addr.port = V4V_PORT_NONE;
      src_id.addr.partner = dst_addr->domain;
    }
  read_unlock (&src_d->v4v->lock);
#endif

  src_id.addr.port = src_addr->port;
  src_id.addr.domain = src_d->domain_id;
  src_id.partner = dst_addr->domain;

  dst_d = get_domain_by_id (dst_addr->domain);
  if (!dst_d)
    {
      read_unlock (&v4v_lock);
      return -ENOTCONN;
    }

  /* XSM: verify if src is allowed to send to dst */
  if (xsm_v4v_send(XSM_HOOK, src_d, dst_d) != 0)
    {
      printk(KERN_ERR "V4V: XSM REJECTED %i -> %i\n",
             src_addr->domain, dst_addr->domain);
      ret = -ENOTCONN;
      goto out;
    }
  /* VIPTables*/
  if (v4v_viptables_check(src_addr, dst_addr) != 0)
    {
      printk(KERN_ERR "V4V: VIPTables REJECTED %i:%u -> %i:%u\n",
             src_addr->domain, src_addr->port,
             dst_addr->domain, dst_addr->port);
      ret = -EPERM;
      goto out;
    }

  do
    {

      if (!dst_d->v4v)
        {
          ret = -ENOTCONN;
          break;
        }

      read_lock (&dst_d->v4v->lock);
      ring_info =
        v4v_ring_find_info_by_addr (dst_d, dst_addr, src_addr->domain);

      if (!ring_info)
          ret = -ENOTCONN;
      else
        {
          long len = v4v_iov_count (iovs, niov);

          if (len < 0)
            {
              ret = len;
              break;
            }

          spin_lock (&ring_info->lock);
          ret =
            v4v_ringbuf_insertv (dst_d, ring_info, &src_id, proto, iovs,
                                 niov, len);
          if (ret == -EAGAIN)
            {
              /* Schedule a wake up on the event channel when space is there */
              if (v4v_pending_requeue (ring_info, src_d->domain_id, len))
                {
                  ret = -ENOMEM;
                }
            }
          spin_unlock (&ring_info->lock);

          if (ret >= 0)
            {
              v4v_signal_domain (dst_d);
            }

        }
      read_unlock (&dst_d->v4v->lock);

    }
  while (1 == 0);

out:
  put_domain (dst_d);
  read_unlock (&v4v_lock);
  return ret;
}

/**************** hypercall glue ************/
long
do_v4v_op (int cmd, XEN_GUEST_HANDLE (void) arg1,
           XEN_GUEST_HANDLE (void) arg2,
           XEN_GUEST_HANDLE (void) arg3, uint32_t arg4, uint32_t arg5)
{
  struct domain *d = current->domain;
  long rc;

  rc = xsm_v4v_use(XSM_HOOK, d);
  if (rc)
      return rc;

#ifdef V4V_DEBUG

  printk (KERN_ERR "->do_v4v_op(%d,%p,%p,%p,%d,%d)\n", cmd,
          (void *) arg1.p, (void *) arg2.p, (void *) arg3.p,
          (int) arg4, (int) arg5);

#endif

  domain_lock (d);

  rc = -EFAULT;
  switch (cmd)
    {
    case V4VOP_register_ring:
      {
        XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd =
          guest_handle_cast (arg1, v4v_ring_t);
        XEN_GUEST_HANDLE (v4v_pfn_list_t) pfn_list_hnd =
          guest_handle_cast (arg2, v4v_pfn_list_t);
        if (unlikely (!guest_handle_okay (ring_hnd, 1)))
          goto out;
        if (unlikely (!guest_handle_okay (pfn_list_hnd, 1))) //FIXME
          goto out;
        rc = v4v_ring_add (d, ring_hnd, pfn_list_hnd);
        break;
      }
    case V4VOP_unregister_ring:
      {
        XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd =
          guest_handle_cast (arg1, v4v_ring_t);
        if (unlikely (!guest_handle_okay (ring_hnd, 1)))
          goto out;
        rc = v4v_ring_remove (d, ring_hnd);
        break;
      }
    case V4VOP_send:
      {
        v4v_addr_t src, dst;
        uint32_t len = arg4;
        uint32_t protocol = arg5;
        XEN_GUEST_HANDLE (v4v_addr_t) src_hnd =
          guest_handle_cast (arg1, v4v_addr_t);
        XEN_GUEST_HANDLE (v4v_addr_t) dst_hnd =
          guest_handle_cast (arg2, v4v_addr_t);

        if (unlikely (!guest_handle_okay (src_hnd, 1)))
          goto out;
        if (copy_from_guest (&src, src_hnd, 1))
          goto out;

        if (unlikely (!guest_handle_okay (dst_hnd, 1)))
          goto out;
        if (copy_from_guest (&dst, dst_hnd, 1))
          goto out;

        rc = v4v_send (d, &src, &dst, protocol, arg3, len);
        break;
      }
    case V4VOP_sendv:
      {
        v4v_addr_t src, dst;
        uint32_t niov = arg4;
        uint32_t protocol = arg5;
        XEN_GUEST_HANDLE (v4v_addr_t) src_hnd =
          guest_handle_cast (arg1, v4v_addr_t);
        XEN_GUEST_HANDLE (v4v_addr_t) dst_hnd =
          guest_handle_cast (arg2, v4v_addr_t);
        XEN_GUEST_HANDLE (v4v_iov_t) iovs =
          guest_handle_cast (arg3, v4v_iov_t);

        if (unlikely (!guest_handle_okay (src_hnd, 1)))
          goto out;
        if (copy_from_guest (&src, src_hnd, 1))
          goto out;

        if (unlikely (!guest_handle_okay (dst_hnd, 1)))
          goto out;
        if (copy_from_guest (&dst, dst_hnd, 1))
          goto out;

        if (unlikely (!guest_handle_okay (iovs, niov)))
          goto out;

        rc = v4v_sendv (d, &src, &dst, protocol, iovs, niov);
        break;
      }
    case V4VOP_notify:
      {
        XEN_GUEST_HANDLE (v4v_ring_data_t) ring_data_hnd =
          guest_handle_cast (arg1, v4v_ring_data_t);
        rc = v4v_notify (d, ring_data_hnd);
        break;
      }
    case V4VOP_viptables_add:
      {
        uint32_t position = arg4;
        XEN_GUEST_HANDLE (v4v_viptables_rule_t) rule_hnd =
          guest_handle_cast (arg1, v4v_viptables_rule_t);
        rc = -EPERM;
        if (!d->is_privileged)
            goto out;
        rc = v4v_viptables_add (d, rule_hnd, position);
        break;
      }
    case V4VOP_viptables_del:
      {
        uint32_t position = arg4;
        XEN_GUEST_HANDLE (v4v_viptables_rule_t) rule_hnd =
          guest_handle_cast (arg1, v4v_viptables_rule_t);
        rc = -EPERM;
        if (!d->is_privileged)
            goto out;
        rc = v4v_viptables_del (d, rule_hnd, position);
        break;
      }
    case V4VOP_viptables_list:
      {
        XEN_GUEST_HANDLE (v4v_viptables_list_t) rules_list_hnd =
            guest_handle_cast(arg1, v4v_viptables_list_t);
        rc = -EPERM;
        if (!d->is_privileged)
            goto out;
        rc = v4v_viptables_list (d, rules_list_hnd);
        break;
      }
    default:
      rc = -ENOSYS;
      break;
    }
out:
  domain_unlock (d);
#ifdef V4V_DEBUG
  printk (KERN_ERR "<-do_v4v_op()=%d\n", (int) rc);
#endif
  return rc;
}




/**************** init *******************/

void
v4v_destroy (struct domain *d)
{
  int i;

  BUG_ON (!d->is_dying);
  write_lock (&v4v_lock);

#ifdef V4V_DEBUG
  printk (KERN_ERR "v4v: %d: d->v=%p\n", __LINE__, d->v4v);
#endif

  if (d->v4v)
  {
    for (i = 0; i < V4V_HTABLE_SIZE; ++i)
      {
        struct hlist_node *node, *next;
        struct v4v_ring_info *ring_info;
        hlist_for_each_entry_safe (ring_info, node,
                                   next, &d->v4v->ring_hash[i],
                                   node) v4v_ring_remove_info (ring_info);
      }
    v4v_xfree(d->v4v);
    d->v4v = NULL;
  }
  write_unlock (&v4v_lock);
}



int
v4v_init (struct domain *d)
{
  struct v4v_domain *v4v;
  int i;

  v4v = v4v_xmalloc (struct v4v_domain);
  if (!v4v)
    return -ENOMEM;

  rwlock_init (&v4v->lock);

  for (i = 0; i < V4V_HTABLE_SIZE; ++i)
    {
      INIT_HLIST_HEAD (&v4v->ring_hash[i]);
    }

  write_lock (&v4v_lock);
  d->v4v = v4v;
  write_unlock (&v4v_lock);

  return 0;
}


/*************************** debug ********************************/

static void
dump_domain_ring (struct domain *d, struct v4v_ring_info *ring_info)
{
  uint32_t rx_ptr;


  printk (KERN_ERR "  ring: domid=%d port=0x%08x partner=%d npage=%d\n",
          (int) d->domain_id, (int) ring_info->id.addr.port,
          (int) ring_info->id.partner, (int) ring_info->npage);

  if (v4v_ringbuf_get_rx_ptr (d, ring_info, &rx_ptr))
    {
      printk (KERN_ERR "   Failed to read rx_ptr\n");
      return;
    }

  printk (KERN_ERR "   tx_ptr=%d rx_ptr=%d len=%d\n",
          (int) ring_info->tx_ptr, (int) rx_ptr, (int) ring_info->len);

}

static void
dump_domain_rings (struct domain *d)
{
  int i;

  printk (KERN_ERR " domain %d:\n", (int) d->domain_id);

  read_lock (&d->v4v->lock);

  for (i = 0; i < V4V_HTABLE_SIZE; ++i)
    {
      struct hlist_node *node;
      struct v4v_ring_info *ring_info;

      hlist_for_each_entry (ring_info, node, &d->v4v->ring_hash[i], node)
        dump_domain_ring (d, ring_info);
    }


  read_unlock (&d->v4v->lock);

  printk (KERN_ERR "\n");
  v4v_signal_domain (d);
}

static void
dump_rings (unsigned char key)
{
  struct domain *d;

  printk (KERN_ERR "\n\nV4V ring dump:\n");
  read_lock (&v4v_lock);

  rcu_read_lock (&domlist_read_lock);

  for_each_domain (d) dump_domain_rings (d);

  rcu_read_unlock (&domlist_read_lock);

  read_unlock (&v4v_lock);
}

struct keyhandler dump_v4v_rings = {
    .diagnostic = 1,
    .u.fn = dump_rings,
    .desc = "dump v4v ring states and interrupt"
};

static int __init
setup_dump_rings (void)
{
  register_keyhandler ('4', &dump_v4v_rings);
  return 0;
}

__initcall (setup_dump_rings);




/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
