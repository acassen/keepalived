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

  See Documentation/rbtree.txt for documentation and samples.
*/

#ifndef	_LINUX_RBTREE_H
#define	_LINUX_RBTREE_H

#include <stdbool.h>

#include "container.h"

typedef struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} rb_node_t;

typedef struct rb_root {
	struct rb_node *rb_node;
} rb_root_t;

/*
 * Leftmost-cached rbtrees.
 *
 * We do not cache the rightmost node based on footprint
 * size vs number of potential users that could benefit
 * from O(1) rb_last(). Just not worth it, users that want
 * this feature can always implement the logic explicitly.
 * Furthermore, users that want to cache both pointers may
 * find it a bit asymmetric, but that's ok.
 */
typedef struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
} rb_root_cached_t;


#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))

#define RB_ROOT	(struct rb_root) { NULL, }
#define RB_ROOT_CACHED (struct rb_root_cached) { {NULL, }, NULL }
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)
#define	rb_entry_const(ptr, type, member) container_of_const(ptr, type, member)

#define RB_EMPTY_ROOT(root)  (((root)->rb_node) == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))


extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);


/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *) __attribute__ ((pure));
extern struct rb_node *rb_prev(const struct rb_node *) __attribute__ ((pure));
extern struct rb_node *rb_first(const struct rb_root *) __attribute__ ((pure));
extern struct rb_node *rb_last(const struct rb_root *) __attribute__ ((pure));

extern void rb_insert_color_cached(struct rb_node *,
				   struct rb_root_cached *, bool);
extern void rb_erase_cached(struct rb_node *node, struct rb_root_cached *);
/* Same as rb_first(), but O(1) */
#define rb_first_cached(root) (root)->rb_leftmost

/* Postorder iteration - always visit the parent after its children */
extern struct rb_node *rb_first_postorder(const struct rb_root *) __attribute__ ((pure));
extern struct rb_node *rb_next_postorder(const struct rb_node *) __attribute__ ((pure));

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new,
			    struct rb_root *root);
extern void rb_replace_node_rcu(struct rb_node *victim, struct rb_node *new,
				struct rb_root *root);
extern void rb_replace_node_cached(struct rb_node *victim, struct rb_node *new,
				   struct rb_root_cached *root);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
				struct rb_node **rb_link)
{
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#ifdef _INCLUDE_UNUSED_CODE_
static inline void rb_link_node_rcu(struct rb_node *node, struct rb_node *parent,
				    struct rb_node **rb_link)
{
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	rcu_assign_pointer(*rb_link, node);
}
#endif

#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})
#define rb_entry_safe_const(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry_const(____ptr, type, member) : NULL; \
	})

/**
 * rbtree_postorder_for_each_entry_safe - iterate in post-order over rb_root of
 * given type allowing the backing memory of @pos to be invalidated
 *
 * @pos:	the 'type *' to use as a loop cursor.
 * @n:		another 'type *' to use as temporary storage
 * @root:	'rb_root *' of the rbtree.
 * @field:	the name of the rb_node field within 'type'.
 *
 * rbtree_postorder_for_each_entry_safe() provides a similar guarantee as
 * list_for_each_entry_safe() and allows the iteration to continue independent
 * of changes to @pos by the body of the loop.
 *
 * Note, however, that it cannot handle other modifications that re-order the
 * rbtree it is iterating over. This includes calling rb_erase() on @pos, as
 * rb_erase() may rebalance the tree, causing us to miss some nodes.
 */
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)

/* The following are keepalived specific code */

/**
 * rb_search -	Search for a specific value in rbtree
 * @root:	the rbtree root.
 * @key:	the key to seach for in your rbtree.
 * @member:	the name of the rb_node within the struct.
 * @compar:	the name of the comparison function to use.
 */
#define rb_search(root, key, member, compar)				\
({									\
	rb_node_t *__n = (root)->rb_node;				\
	typeof(key) __ret = NULL, __data;				\
									\
	while (__n) {							\
		__data = rb_entry(__n, typeof(*key), member);		\
		int __cmp = compar(key, __data);			\
									\
		if (__cmp < 0)						\
			__n = __n->rb_left;				\
		else if (__cmp > 0)					\
			__n = __n->rb_right;				\
		else {							\
			__ret = __data;					\
			break;						\
		}							\
	}								\
	__ret;								\
})

/**
 * rb_search_first -	Search for the first greater value in rbtree
 * @root:		the rbtree root.
 * @key:		the key to seach for in your rbtree.
 * @member:		the name of the rb_node within the struct.
 * @compar:		the name of the comparison function to use.
 */
#define rb_search_first(root, key, member, compar)			\
({									\
	rb_node_t *__n = (root)->rb_node;				\
	typeof(key) __ret = NULL, __data;				\
									\
	while (__n) {							\
		__data = rb_entry(__n, typeof(*key), member);		\
		int __cmp = compar(key, __data);			\
									\
		if (__cmp < 0) {					\
			__ret = __data;					\
			__n = __n->rb_left;				\
		} else if (__cmp > 0)					\
			__n = __n->rb_right;				\
		else {							\
			__ret = __data;					\
			break;						\
		}							\
	}								\
	if (!__ret && !RB_EMPTY_ROOT(root))				\
		__ret = rb_entry(rb_first(root), typeof(*key), member); \
	__ret;								\
})

/**
 * rb_insert -	Insert a new node into your rbtree
 * @root:	the rbtree root.
 * @new:	the node to insert.
 * @member:	the name of the rb_node within the struct.
 * @compar:	the name of the comparison function to use.
 */
#define rb_insert(root, new, member, compar)				\
({									\
	rb_node_t **__n = &(root)->rb_node, *__parent = NULL;		\
	typeof(new) __old = NULL, __data;				\
									\
	while (*__n) {							\
		__data = rb_entry(*__n, typeof(*new), member);		\
		int __cmp = compar(new, __data);			\
									\
		__parent = *__n;					\
		if (__cmp < 0)						\
			__n = &((*__n)->rb_left);			\
		else if (__cmp > 0)					\
			__n = &((*__n)->rb_right);			\
		else {							\
			__old = __data;					\
			break;						\
		}							\
	}								\
									\
	if (__old == NULL) {						\
		/* Add new node and rebalance tree. */			\
		rb_link_node(&((new)->member), __parent, __n);		\
		rb_insert_color(&((new)->member), root);		\
	}								\
									\
	__old;								\
})

/**
 * rb_insert -	Insert & Sort a new node into your rbtree
 * @root:	the rbtree root.
 * @new:	the node to insert.
 * @member:	the name of the rb_node within the struct.
 * @compar:	the name of the comparison function to use.
 */
#define rb_insert_sort(root, new, member, compar)			\
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
 * rb_insert_cached - Insert & Sort a new node into your cached rbtree
 * @root:       the rbtree root.
 * @new:        the node to insert.
 * @member:     the name of the rb_node within the struct.
 * @compar:     the name of the comparison function to use.
 */
#define rb_insert_sort_cached(root, new, member, compar)		\
({									\
        rb_node_t **__n = &(root)->rb_root.rb_node, *__parent = NULL;	\
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
	/* Add new node and rebalance tree. */				\
	rb_link_node(&((new)->member), __parent, __n);			\
	rb_insert_color_cached(&((new)->member), root,			\
				!(root)->rb_leftmost || __n == &(root)->rb_leftmost->rb_left);	\
})

/**
 * rb_for_each_entry -  Iterate over rbtree of given type
 * @pos:		the type * to use as a loop cursor.
 * @root:		the rbtree root.
 * @member:		the name of the rb_node within the struct.
 */
#define rb_for_each_entry(pos, root, member)				\
	for (pos = rb_entry_safe(rb_first(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe(rb_next(&pos->member), typeof(*pos), member))
#define rb_for_each_entry_const(pos, root, member)				\
	for (pos = rb_entry_safe_const(rb_first(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe_const(rb_next(&pos->member), typeof(*pos), member))

/**
 * rb_for_each_entry_safe - 	Iterate over rbtree of given type safe against removal
 * @pos:			the type * to use as a loop cursor.
 * @root:			the rbtree root.
 * @member:			the name of the rb_node within the struct.
 */
#define rb_for_each_entry_safe(pos, n, root, member)					\
	for (pos = rb_entry_safe(rb_first(root), typeof(*pos), member);			\
	     pos && (n = rb_entry_safe(rb_next(&pos->member), typeof(*n), member), 1);	\
	     pos = n)

/**
 * rb_for_each_entry_cached -  Iterate over cached rbtree of given type
 * @pos:                the type * to use as a loop cursor.
 * @root:               the rbtree root.
 * @member:             the name of the rb_node within the struct.
 */
#define rb_for_each_entry_cached(pos, root, member)				\
	for (pos = rb_entry_safe(rb_first_cached(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe(rb_next(&pos->member), typeof(*pos), member))
#define rb_for_each_entry_cached_const(pos, root, member)				\
	for (pos = rb_entry_safe_const(rb_first_cached(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe_const(rb_next(&pos->member), typeof(*pos), member))

/**
 * rb_for_each_entry_safe_cached - Iterate over cached rbtree of given type
 * @pos:                the type * to use as a loop cursor.
 * @root:               the rbtree root.
 * @member:             the name of the rb_node within the struct.
 */
#define rb_for_each_entry_safe_cached(pos, n, root, member)				\
	for (pos = rb_entry_safe(rb_first_cached(root), typeof(*pos), member);		\
	     pos && (n = rb_entry_safe(rb_next(&pos->member), typeof(*n), member), 1);	\
	     pos = n)

/**
 * rb_for_each_entry_from -	Iterate over rbtree of given type from the given point
 * @pos:			the type * to use as a loop cursor.
 * @root:			the rbtree root.
 * @member:			the name of the rb_node within the struct.
 */
#define rb_for_each_entry_from(pos, root, member)			\
	for (rb_node_t *n = &pos->member;				\
	     n && pos = rb_entry(n, typeof(*pos), member);		\
	     n = rb_next(n))

/**
 * rb_move_cached -	Move node to new position in tree
 * @root:		the rbtree root.
 * @node:		the node to move.
 * @member:		the name of the rb_node within the struct.
 * @compar:		the name of the comparison function to use.
 */
#define rb_move_cached(root, node, member, compar)				\
({										\
	rb_node_t *prev_node, *next_node;					\
	typeof(node) prev, next;						\
										\
	prev_node = rb_prev(&node->member);					\
	next_node = rb_next(&node->member);					\
										\
	if (prev_node || next_node) {						\
		prev = rb_entry_safe(prev_node, typeof(*node), member);		\
		next = rb_entry_safe(next_node, typeof(*node), member);		\
										\
		/* If node is between our predecessor and sucessor,		\
		 * it can stay where it is */					\
		if ((prev && compar(prev, node) > 0) ||				\
		    (next && compar(next, node) < 0)) {				\
			/* Can this be optimised? */				\
			rb_erase_cached(&node->member, root);			\
			rb_insert_sort_cached(root, node, member, compar);	\
		}								\
	}									\
})

#endif	/* _LINUX_RBTREE_H */
