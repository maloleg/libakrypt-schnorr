# Инструкция по встраиванию

В настоящей главе мы приводим рекомендации по использованию и встраиванию библиотеки `libakrypt`
в программные средства. Рекомендации оформлены в виде примеров,
иллюстрирующих основные функциональные особенности библиотеки.

Перечень экспортируемых библиотекой констант, типов данных и функций содержится в заголовочном
файле `libakrypt.h`. Для встраивания библиотеки должны использоваться только экспортируемые функции.
Вызов не экспортируемых функций библиотеки считается недопустимым и не должен применяться при
использовании библиотеки.

\section tinit Инициализация

\subsection tinit_libex1 Пример инициализации библиотеки

Перед тем, как вызывать какие-либо функции библиотеки, необходимо провести ее инициализацию.
Для этого предназначена функция ak_libakrypt_create() - функция выполняет проверку корректности работы
криптографических механизмов и инициализирует внутренние переменные библиотеки.

Простейшая программа (\ref example-hello.c), использующая библиотеку,
должна выглядеть следующим образом.

\include examples/example-hello.c

Обратим внимание, что используемая для инициализации библиотеки функция ak_libakrypt_create() принимает один параметр,
а именно, указатель на функцию, которая используется для вывода сообщений о работе или ошибках библиотеки.

Завершение работы с функциями библиотеки должно производиться
при помощи вызова функции ak_libakrypt_destroy(). Данная функция останавливает внутренние механизмы
и освобождает используемую библиотекой память.

\subsection tinit_libex2 Пример установки пользовательской функции аудита

В заголовочном файле `libakrypt.h` содержится перечень из нескольких заранее предопределенных функций,
предназначенных для вывода сообщений, например

* ak_function_log_stderr() - данная функция использует для вывода сообщений стандартный поток вывода ошибок
операционной системы; реализация данной функции доступна для всех операционных систем;

* ak_function_log_syslog() - данная функция использует для вывода сообщений демон операционной системы
`syslogd` или его аналог, предназначенный для журналирования событий в системе; реализация данной функции
доступна только в unix-операционных системах.

Пользователь может самостоятельно определить и использовать свою собственную функцию
вывода сообщений об ошибках, настроив вывод сообщений библиотеки
наиболее удобным способом.  Для этого пользователь должен реализовать функцию,
удовлетворяющую следующему определению

\code
/* Определение функции аудита */
    typedef int ( ak_function_log )( const char * );
\endcode

Приведем простой пример (\ref example-log.c) в котором используется функция ak_log_set_function().
Эта функция устанавливает пользовательскую функцию аудита.

\include examples/example-log.c

Обратим внимание на то, что все функции библиотеки, и в часттности main(),
могут использовать для вывода сообщений функцию ak_log_set_message().
