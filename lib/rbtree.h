/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/include/linux/rbtree.h

  To use rbtrees you'll have to implement your own insert and search cores.
  This will avoid us to use callbacks and to drop drammatically performances.
  I know it's not the cleaner way,  but in C (not in C++) to get
  performances and genericity...

  Some example of insert and search follows here. The search is a plain
  normal search over an ordered tree. The insert instead must be implemented
  int two steps: as first thing the code must insert the element in
  order as a red leaf in the tree, then the support library function
  rb_insert_color() must be called. Such function will do the
  not trivial work to rebalance the rbtree if necessary.

-----------------------------------------------------------------------
static inline struct page * rb_search_page_cache(struct inode * inode,
						 unsigned long offset)
{
	struct rb_node * n = inode->i_rb_page_cache.rb_node;
	struct page * page;

	while (n)
	{
		page = rb_entry(n, struct page, rb_page_cache);

		if (offset < page->offset)
			n = n->rb_left;
		else if (offset > page->offset)
			n = n->rb_right;
		else
			return page;
	}
	return NULL;
}

static inline struct page * __rb_insert_page_cache(struct inode * inode,
						   unsigned long offset,
						   struct rb_node * node)
{
	struct rb_node ** p = &inode->i_rb_page_cache.rb_node;
	struct rb_node * parent = NULL;
	struct page * page;

	while (*p)
	{
		parent = *p;
		page = rb_entry(parent, struct page, rb_page_cache);

		if (offset < page->offset)
			p = &(*p)->rb_left;
		else if (offset > page->offset)
			p = &(*p)->rb_right;
		else
			return page;
	}

	rb_link_node(node, parent, p);

	return NULL;
}

static inline struct page * rb_insert_page_cache(struct inode * inode,
						 unsigned long offset,
						 struct rb_node * node)
{
	struct page * ret;
	if ((ret = __rb_insert_page_cache(inode, offset, node)))
		goto out;
	rb_insert_color(node, &inode->i_rb_page_cache);
 out:
	return ret;
}
-----------------------------------------------------------------------
*/

#ifndef	_LINUX_RBTREE_H
#define	_LINUX_RBTREE_H

typedef struct rb_node
{
	unsigned long  rb_parent_color;
#define	RB_RED		0
#define	RB_BLACK	1
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} rb_node_t;

typedef struct rb_root
{
	struct rb_node *rb_node;
} rb_root_t;

/* Copy from linux kernel 2.6 source (kernel.h, stddef.h) */
#ifndef container_of
# define container_of(ptr, type, member) ({      \
         const typeof( ((type *)0)->member ) *__mptr = (ptr);  \
         (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef offsetof
# define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif


#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_red(r)   (!rb_color(r))
#define rb_is_black(r) rb_color(r)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)

static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
	rb->rb_parent_color = (rb->rb_parent_color & 3) | (unsigned long)p;
}
static inline void rb_set_color(struct rb_node *rb, int color)
{
	rb->rb_parent_color = (rb->rb_parent_color & ~1) | color;
}

#define RB_ROOT	(struct rb_root) { NULL, }
#define	rb_entry(ptr, type, member) (ptr) ? container_of(ptr, type, member) : NULL

#define RB_EMPTY_ROOT(root)	((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node)	(rb_parent(node) == node)
#define RB_CLEAR_NODE(node)	(rb_set_parent(node, node))

extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);

/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new,
			    struct rb_root *root);

static inline void rb_link_node(struct rb_node * node, struct rb_node * parent,
				struct rb_node ** rb_link)
{
	node->rb_parent_color = (unsigned long )parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

/**
 * rb_search -  Search for a specific value in rbtree
 * @root:       the rbtree root.
 * @key:        the key to seach for in your rbtree.
 * @member:     the name of the rb_node within the struct.
 * @compar:     the name of the comparison function to use.
 */
#define rb_search(root, key, member, compar)                            \
({                                                                      \
        rb_node_t *__n = (root)->rb_node;                               \
        typeof(key) __ret = NULL, __data;                               \
                                                                        \
        while (__n) {                                                   \
                __data = rb_entry(__n, typeof(*key), member);           \
                int __cmp = compar(key, __data);                        \
                                                                        \
                if (__cmp < 0)                                          \
                        __n = __n->rb_left;                             \
                else if (__cmp > 0)                                     \
                        __n = __n->rb_right;                            \
                else {                                                  \
                        __ret = __data;                                 \
                        break;                                          \
                }                                                       \
        }                                                               \
        __ret;                                                          \
})

/**
 * rb_search_first -  Search for the first greater value in rbtree
 * @root:             the rbtree root.
 * @key:              the key to seach for in your rbtree.
 * @member:           the name of the rb_node within the struct.
 * @compar:           the name of the comparison function to use.
 */
#define rb_search_first(root, key, member, compar)		\
({                                                                      \
        rb_node_t *__n = (root)->rb_node;				\
        typeof(key) __ret = NULL, __data;                               \
                                                                        \
        while (__n) {                                                   \
                __data = rb_entry(__n, typeof(*key), member);           \
                int __cmp = compar(key, __data);                        \
                                                                        \
                if (__cmp < 0) {                                        \
                        __ret = __data;                                 \
                        __n = __n->rb_left;                             \
                } else if (__cmp > 0)                                   \
                        __n = __n->rb_right;                            \
                else {                                                  \
                        __ret = __data;                                 \
                        break;                                          \
                }                                                       \
        }                                                               \
        if (!__ret && !RB_EMPTY_ROOT(root))                             \
                __ret = rb_entry(rb_first(root), typeof(*key), member); \
        __ret;                                                          \
})

/**
 * rb_insert -  Insert a new node into your rbtree
 * @root:       the rbtree root.
 * @new:        the node to insert.
 * @member:     the name of the rb_node within the struct.
 * @compar:     the name of the comparison function to use.
 */
#define rb_insert(root, new, member, compar)                            \
({                                                                      \
        rb_node_t **__n = &(root)->rb_node, *__parent = NULL;           \
        typeof(new) __old = NULL, __data;                               \
                                                                        \
        while (*__n) {                                                  \
                __data = rb_entry(*__n, typeof(*new), member);          \
                int __cmp = compar(new, __data);                        \
                                                                        \
                __parent = *__n;                                        \
                if (__cmp < 0)                                          \
                        __n = &((*__n)->rb_left);                       \
                else if (__cmp > 0)                                     \
                        __n = &((*__n)->rb_right);                      \
                else {                                                  \
                        __old = __data;                                 \
                        break;                                          \
                }                                                       \
        }                                                               \
                                                                        \
        if (__old == NULL) {                                            \
                /* Add new node and rebalance tree. */                  \
                rb_link_node(&((new)->member), __parent, __n);          \
                rb_insert_color(&((new)->member), root);                \
        }                                                               \
                                                                        \
        __old;                                                          \
})

/**
 * rb_insert -  Insert & Sort a new node into your rbtree
 * @root:       the rbtree root.
 * @new:        the node to insert.
 * @member:     the name of the rb_node within the struct.
 * @compar:     the name of the comparison function to use.
 */
#define rb_insert_sort(root, new, member, compar)				\
({									\
        rb_node_t **__n = &(root)->rb_node, *__parent = NULL;		\
        typeof(new) __data;						\
									\
        while (*__n) {							\
                __data = rb_entry(*__n, typeof(*new), member);		\
                int __cmp = compar(new, __data);			\
									\
                __parent = *__n;					\
                if (__cmp <= 0)						\
                        __n = &((*__n)->rb_left);			\
                else if (__cmp > 0)					\
                        __n = &((*__n)->rb_right);			\
        }								\
									\
	/* Add new node and rebalance tree. */				\
	rb_link_node(&((new)->member), __parent, __n);			\
	rb_insert_color(&((new)->member), root);			\
})

/**
 * rb_for_each_entry -  Iterate over rbtree of given type
 * @pos:                the type * to use as a loop cursor.
 * @root:               the rbtree root.
 * @member:             the name of the rb_node within the struct.
 */
#define rb_for_each_entry(pos, root, member)				\
	for (pos = rb_entry(rb_first(root), typeof(*pos), member);	\
	     pos; pos = rb_entry(rb_next(&pos->member), typeof(*pos), member))

/**
 * rb_for_each_entry_safe -  Iterate over rbtree of given type safe against removal
 * @pos:                     the type * to use as a loop cursor.
 * @root:                    the rbtree root.
 * @member:                  the name of the rb_node within the struct.
 */
#define rb_for_each_entry_safe(pos, n, root, member)				\
	for (pos = rb_entry(rb_first(root), typeof(*pos), member);		\
	     pos && (n = rb_entry(rb_next(&pos->member), typeof(*n), member), 1);	\
	     pos = n)

/**
 * rb_for_each_entry_from -  Iterate over rbtree of given type from the given point
 * @pos:                     the type * to use as a loop cursor.
 * @root:                    the rbtree root.
 * @member:                  the name of the rb_node within the struct.
 */
#define rb_for_each_entry_from(pos, root, member)			\
	for (rb_node_t *n = &pos->member;				\
	     n && pos = rb_entry(n, typeof(*pos), member);		\
	     n = rb_next(n))

/**
 * rb_move -    Move node to new position in tree
 * @root:       the rbtree root.
 * @node:       the node to move.
 * @member:     the name of the rb_node within the struct.
 * @compar:     the name of the comparison function to use.
 */
#define rb_move(root, node, member, compar)					\
({										\
	rb_node_t *prev_node, *next_node;					\
	typeof(node) prev = NULL, next = NULL;					\
										\
	prev_node = rb_prev(&node->member);					\
	next_node = rb_next(&node->member);					\
										\
	if (prev_node || next_node) {						\
		prev = rb_entry(prev_node, typeof(*node), member);		\
		next = rb_entry(next_node, typeof(*node), member);		\
										\
		/* If node is between our predecessor and sucessor,		\
		 * it can stay where it is */					\
		if ((prev && compar(prev, node) > 0) ||				\
		    (next && compar(next, node) < 0)) {				\
			/* Can this be optimised? */				\
			rb_erase(&node->member, root);				\
			rb_insert_sort(root, node, member, compar);		\
		}								\
	}									\
})

#endif	/* _LINUX_RBTREE_H */
