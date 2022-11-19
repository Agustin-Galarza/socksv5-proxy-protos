#ifndef USERLIST_H_
#define USERLIST_H_

#include <stdbool.h>
#include <stdio.h>

typedef struct user_list user_list_t;

struct user_list_user {
    char* username;
    char* password;
};

user_list_t* user_list_init(size_t capacity);
void user_list_free(user_list_t* list);

/**
 * Agrega un nuevo usuario a la lista.
 * Retorna true si el usuario fue agregado, false en caso contrario.
 * Tanto username como password tienen que ser strings terminados en '\0'.
 * La lista se guarda una COPIA de los valores de username y password
 */
bool user_list_add(user_list_t* list, char* username, char* password);

bool user_list_contains(user_list_t* list, char* username, char* password);

/**
 * Elimina de la lista al usuario de username y password indicados en caso de que exista.
 * Retorna true si el usuario fue eliminado, false en caso contrario
 */
bool user_list_remove(user_list_t* list, char* username, char* password);

size_t user_list_size(user_list_t* list);

// Devuelve al usuario en la posición index, un usuario inválido de no existir
struct user_list_user user_list_get(user_list_t* list, size_t index);

// Devuelve true si user representa a un usuario válido o no
bool user_list_is_valid_user(struct user_list_user* user);

/**
 * recorre toda la lista de usuarios y a cada uno de ellos se lo pasa por parámetro a la función consumer
 */
void user_list_for_each(user_list_t* list, void (*consumer)(struct user_list_user*));

#endif
