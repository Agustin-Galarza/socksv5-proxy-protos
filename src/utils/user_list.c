#include <string.h>
#include <stdlib.h>

#include "utils/user_list.h"

typedef struct user_node
{
    char* username;
    char* password;
    struct user_node* next;
} user_node_t;

struct user_list {
    user_node_t* start;
    size_t capacity;
    size_t size;
};

user_list_t* user_list_init(size_t capacity) {
    user_list_t* list = calloc(sizeof(struct user_list), 1);
    list->capacity = capacity;
    return list;
}

static inline void
free_usr(user_node_t* usr) {
    if (usr == NULL) return;
    if (usr->username != NULL)
        free(usr->username);
    if (usr->password != NULL)
        free(usr->password);
    free(usr);
}

void user_list_free(user_list_t* list) {
    if (list != NULL) {
        user_node_t* curr = list->start;
        while (curr != NULL) {
            user_node_t* aux = curr;
            curr = curr->next;
            free_usr(aux);
        }
        free(list);
    }
}

static user_node_t* new_user(char* username, char* password) {
    user_node_t* usr_node = malloc(sizeof(user_node_t));
    size_t username_len = strlen(username) + 1;
    size_t password_len = strlen(password) + 1;
    char* username_copy = malloc(username_len);
    char* password_copy = malloc(password_len);
    strncpy(username_copy, username, username_len);
    strncpy(password_copy, password, password_len);

    usr_node->username = username_copy;
    usr_node->password = password_copy;
    usr_node->next = NULL;
    return usr_node;
}

bool user_list_add(user_list_t* list, char* username, char* password) {
    if (list->size == list->capacity)
        return false;

    if (list->start == NULL) {
        list->start = new_user(username, password);
        list->size++;
        return true;
    }
    user_node_t* curr = list->start;
    for (; curr->next != NULL; curr = curr->next);
    curr->next = new_user(username, password);
    list->size++;
    return true;
}

inline static bool
found_user(user_node_t* user, char* username, char* password) {
    return (strcmp(user->username, username) == 0 &&
            strcmp(user->password, password) == 0);
}

static inline void remove_usr(user_node_t* target, user_node_t* prev) {
    prev->next = target->next;
    free_usr(target);
}

bool user_list_remove(user_list_t* list, char* username, char* password) {
    if (list->size == 0)
        return false;

    if (found_user(list->start, username, password)) {
        user_node_t* aux = list->start;
        list->start = list->start->next;
        free_usr(aux);
        list->size--;
        return true;
    }
    user_node_t* prev = list->start;
    user_node_t* curr = list->start->next;
    for (; curr != NULL; curr = curr->next) {
        if (found_user(curr, username, password)) {
            remove_usr(curr, prev);
            list->size--;
            return true;
        }
        prev = curr;
    }
    return false;
}

size_t user_list_size(user_list_t* list) {
    return list->size;
}

bool user_list_contains(user_list_t* list, char* username, char* password) {
    for (user_node_t* curr = list->start; curr != NULL; curr = curr->next) {
        if (found_user(curr, username, password))
            return true;
    }
    return false;
}

struct user_list_user user_list_get(user_list_t* list, size_t index) {
    struct user_list_user ret = { 0 };
    if (index >= list->size)
        return ret;
    user_node_t* curr;
    for (curr = list->start; curr != NULL && index-- > 0; curr = curr->next);
    if (curr != NULL) {
        ret.username = curr->username;
        ret.password = curr->password;
    }
    return ret;
}

bool user_list_is_valid_user(struct user_list_user* user) {
    return user->username == NULL;
}

void user_list_for_each(user_list_t* list, void (*consumer)(struct user_list_user*)) {
    struct user_list_user usr;
    for (user_node_t* curr = list->start; curr != NULL; curr = curr->next) {
        usr.username = curr->username;
        usr.password = curr->password;
        consumer(&usr);
    }
}

