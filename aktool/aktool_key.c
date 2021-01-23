/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры выработки ключевой информации,                        */
/*  используемой криптографическими алгоритмами библиотеки libakrypt                               */
/*                                                                                                 */
/*  aktool_key.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
/* Предварительное описание используемых функций */
 int aktool_key_help( void );
 int aktool_key_new( void );
 int aktool_key_new_blom_master( void );
 int aktool_key_new_blom_subscriber( void );
 int aktool_key_new_blom_pairwise( void );
 int aktool_key_new_keypair( bool_t , bool_t );
 int aktool_key_show_key( void );
 int aktool_key_show_secret_key( void );
 int aktool_key_show_public_key( void );
 int aktool_key_input_name( ak_verifykey );
 int aktool_key_input_name_from_console( ak_verifykey );
/* функция для вывода информации о полях сертификата */
 int aktool_certificate_out( const char *message ) {
   fprintf( stdout, "%s", message );
  return ak_error_ok;
 }


/* ----------------------------------------------------------------------------------------------- */
#define aktool_magic_number (113)

/* ----------------------------------------------------------------------------------------------- */
 static struct key_info {
   ak_oid method;
   ak_oid oid_of_generator, oid_of_target;
   char *name_of_file_for_generator;
   export_format_t format;
   ak_oid curve;
   size_t days;
   ak_uint32 field, size;
   int target_undefined;
   ssize_t lenpass, lenkeypass, lenuser;
   struct certificate_opts opts;
   char password[aktool_password_max_length];
   char key_password[aktool_password_max_length];
   char keylabel[256];
   char user[512]; /* идентификатор пользователя ключа */

   char os_file[FILENAME_MAX];   /* сохраняем, секретный ключ */
   char op_file[FILENAME_MAX];    /* сохраняем, открытый ключ */
   char key_file[FILENAME_MAX];     /* читаем, секретный ключ */
   char pubkey_file[FILENAME_MAX];   /* читаем, открытый ключ */
 } ki;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, char *argv[] )
{
  char tmp[4];
  size_t i = 0;
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new, do_cert, do_show } work = do_nothing;

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "new",                 0, NULL,  'n' },
     { "show",                1, NULL,  's' },
     { "output-secret-key",   1, NULL,  'o' },
     { "to",                  1, NULL,  250 },
     { "format",              1, NULL,  250 },
     { "hexpass",             1, NULL,  249 },
     { "password",            1, NULL,  248 },
     { "key-hexpass",         1, NULL,  251 },
     { "key-password",        1, NULL,  252 },
     { "curve",               1, NULL,  247 },
     { "days",                1, NULL,  246 },

     { "pubkey",              1, NULL,  208 },
     { "label",               1, NULL,  207 },
     { "random-file",         1, NULL,  206 },
     { "random",              1, NULL,  205 },
     { "key",                 1, NULL,  203 },
     { "op",                  1, NULL,  202 },
     { "output-public-key",   1, NULL,  202 },

   /* флаги для генерации ключей схемы Блома */
     { "field",               1, NULL,  180 },
     { "size",                1, NULL,  181 },
     { "id",                  1, NULL,  182 },
     { "hexid",               1, NULL,  183 },
     { "target",              1, NULL,  't' },

    /* флаги использования открытого ключа */
     { "digital-signature",   0, NULL,  190 },
     { "content-commitment",  0, NULL,  191 },
     { "key-encipherment",    0, NULL,  192 },
     { "data-encipherment",   0, NULL,  193 },
     { "key-agreement",       0, NULL,  194 },
     { "key-cert-sign",       0, NULL,  195 },
     { "crl-sign",            0, NULL,  196 },
     { "ca",                  1, NULL,  197 },
     { "pathlen",             1, NULL,  198 },
     { "authority-keyid",     0, NULL,  199 },
     { "authority-name",      0, NULL,  200 },

     aktool_common_functions_definition,
     { NULL,                  0, NULL,   0  },
  };

 /* инициализируем множество параметров по-умолчанию */
  memset( &ki, 0, sizeof( struct key_info ));
  ki.method = NULL;
  ki.oid_of_target = NULL;
  ki.oid_of_generator = ak_oid_find_by_name( aktool_default_generator );
  ki.name_of_file_for_generator = NULL;
  ki.format = asn1_der_format;
  ki.curve = ak_oid_find_by_name( "id-tc26-gost-3410-2012-256-paramSetA" );
  ki.days = 365;
 /* параметры секретного ключа для схемы Блома */
  ki.field = ak_galois256_size;
  ki.size = 512;
  ak_certificate_opts_create( &ki.opts );
 /*  далее ki состоит из одних нулей */

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "hns:a:o:t:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_key_help );

      /* управляющие команды */
        case 'n' :  work = do_new;
                    break;
        case 's' :  work = do_show; /* присваиваем имя key_file */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                    realpath( optarg , ki.key_file );
                  #endif
                    break;

      /* устанавливаем имя криптографического алгоритма генерации ключей */
        case 'a' :  if(( ki.method = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(_("using unsupported name or identifier \"%s\""), optarg );
                      printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                    }
                    if( ki.method->mode != algorithm ) {
                      aktool_error(_("%s is not valid identifier for algorithm"), optarg );
                      printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                      return EXIT_FAILURE;
                    }
                    break;

      /* устанавливаем имя криптографического алгоритма для которого вырабатывается ключ */
        case 't' : /* --target */
                   if( strncmp( optarg, "undefined", 9 ) == 0 ) {
                     ki.oid_of_target = NULL;
                     ki.target_undefined = ak_true;
                     break;
                   }
                   ki.target_undefined = ak_false;
                   if(( ki.oid_of_target = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(_("using unsupported name or identifier \"%s\""), optarg );
                      printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if( ki.oid_of_target->mode != algorithm ) {
                     aktool_error(_("%s is not valid identifier for algorithm"), optarg );
                     printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                   }
                   break;

      /* устанавливаем имя генератора ключевой информации */
        case 205:   if(( ki.oid_of_generator = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(
                        _("using unsupported name or identifier \"%s\" for random generator"),
                                                                                          optarg );
                      printf(
                     _("try \"aktool s --oid random\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                    }
                    if(( ki.oid_of_generator->engine != random_generator ) ||
                                                     ( ki.oid_of_generator->mode != algorithm )) {
                      aktool_error(_("%s is not valid identifier for random generator"), optarg );
                      printf(
                     _("try \"aktool s --oid random\" for list of all available algorithms\n"));
                      return EXIT_FAILURE;
                    }
                    break;

      /* устанавливаем имя файла для генератора ключевой информации */
        case 206:   ki.name_of_file_for_generator = optarg;
                    break;

      /* запоминаем упользовательское описание ключа */
        case 207:   memcpy( ki.keylabel, optarg,
                                              ak_min( strlen( optarg ), sizeof( ki.keylabel )-1 ));
                    break;

      /* устанавливаем размер конечного поля (в битах) */
        case 180: /* --field */
                   ki.field = atoi( optarg );
                   if(( ki.field != ak_galois256_size ) && ( ki.field != ak_galois512_size )) {
                     if( ki.field == 256 ) ki.field >>= 3;
                       else
                        if( ki.field == 512 ) ki.field >>= 3;
                          else {
                            aktool_error(_("incorrect value of field size,"
                                                " use \"--field 256\" or \"--field 512\" option"));
                            return EXIT_FAILURE;
                          }
                   }
                   break;

      /* устанавливаем размер матрицы (мастер-ключа) для схемы Блома */
        case 181: /* --size */
                   if(( ki.size = atoi( optarg )) == 0 ) ki.size = 512;
                   if( ki.size > 4096 ) ki.size = 4096; /* ограничение по реализации */
                   break;

      /* устанавливаем идентификатор/расширенное имя пользователя или владельца */
        case 182: /* --id */
                   memset( ki.user, 0, sizeof( ki.user ));
                   strncpy( ki.user, optarg, sizeof( ki.user ) -1 );
                   ki.lenuser = strlen( ki.user );
                   break;

        case 183: /* --hexid */
                   ki.lenuser = 0;
                   memset( ki.user, 0, sizeof( ki.user ));
                   if( ak_hexstr_to_ptr( optarg, ki.user,
                                              sizeof( ki.user ), ak_false ) == ak_error_ok ) {
                      ki.lenuser = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                                sizeof( ki.user ));
                   }
                   if( ki.lenuser == 0 ) {
                       aktool_error(_("user identifier cannot be of zero length, "
                                                       "maybe input error, see --hexid %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

      /* передача паролей через командную строку */
        case 248: /* --password */
                   memset( ki.password, 0, sizeof( ki.password ));
                   strncpy( ki.password, optarg, sizeof( ki.password ) -1 );
                   if(( ki.lenpass = strlen( ki.password )) == 0 ) {
                     aktool_error(_("password cannot be of zero length"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 252: /* --key-password */
                   memset( ki.key_password, 0, sizeof( ki.key_password ));
                   strncpy( ki.key_password, optarg, sizeof( ki.key_password ) -1 );
                   if(( ki.lenkeypass = strlen( ki.key_password )) == 0 ) {
                     aktool_error(_("password cannot be of zero length"));
                     return EXIT_FAILURE;
                   }
                   break;

      /* передача паролей через командную строку в шестнадцатеричном виде */
        case 249: /* --hexpass */
                   ki.lenpass = 0;
                   memset( ki.password, 0, sizeof( ki.password ));
                   if( ak_hexstr_to_ptr( optarg, ki.password,
                                              sizeof( ki.password ), ak_false ) == ak_error_ok ) {
                     ki.lenpass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                            sizeof( ki.password ));
                   }
                   if( ki.lenpass == 0 ) {
                       aktool_error(_("password cannot be of zero length, "
                                                       "maybe input error, see --hexpass %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

        case 251: /* --key-hexpass */
                   ki.lenkeypass = 0;
                   memset( ki.key_password, 0, sizeof( ki.key_password ));
                   if( ak_hexstr_to_ptr( optarg, ki.key_password,
                                           sizeof( ki.key_password ), ak_false ) == ak_error_ok ) {
                     ki.lenkeypass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                         sizeof( ki.key_password ));
                   }
                   if( ki.lenkeypass == 0 ) {
                       aktool_error(_("password cannot be of zero length, "
                                                       "maybe input error, see --hexpass %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

      /* интервал действия ключа */
        case 246: /* --days */
                    ki.days = atoi( optarg );
                    if( !ki.days ) ki.days = 365;
                    break;

      /* проверяем идентификатор кривой */
        case 247: /* --curve  */
                   if(( ki.curve = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(
                        _("using unsupported name or identifier \"%s\" for elliptic curve"),
                                                                                          optarg );
                     printf(
                        _("try \"aktool s --oid curve\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if(( ki.curve->engine != identifier ) || ( ki.curve->mode != wcurve_params )) {
                      aktool_error(_("%s is not valid identifier for elliptic curve"), optarg );
                      printf(
                        _("try \"aktool s --oid curve\" for list of all available identifiers\n"));
                       return EXIT_FAILURE;
                     }
                   break;

      /* устанавливаем имена файлов (в полном, развернутом виде) */
        case 'o': /* --o, --output-secret-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.os_file, NULL );
                  #else
                    realpath( optarg , ki.os_file );
                  #endif
                    break;

        case 202: /* --op, --output-public-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.op_file, NULL );
                  #else
                    realpath( optarg , ki.op_file );
                  #endif
                    break;

        case 203: /* --key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                    realpath( optarg , ki.key_file );
                  #endif
                    break;

        case 208: /* --pubkey */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.pubkey_file, NULL );
                  #else
                    realpath( optarg , ki.pubkey_file );
                  #endif
                    break;

      /* определяем формат выходных данных */
        case 250: /* --to, --format  */
                   memset( tmp, 0, sizeof( tmp ));
                   strncpy( tmp, optarg, 3 );
                   for( i = 0; i < sizeof( tmp )-1; i ++ ) tmp[i] = toupper( tmp[i] );

                   ki.format = asn1_der_format;
                   if( strncmp( tmp, "DER", 3 ) == 0 )
                     ki.format = asn1_der_format;
                    else
                      if( strncmp( tmp, "PEM", 3 ) == 0 )
                        ki.format = asn1_pem_format;
                       else
                         if( strncmp( tmp, "CER", 3 ) == 0 )
                           ki.format = aktool_magic_number;
                          else {
                             aktool_error(_("%s is not valid format of output data"), optarg );
                             return EXIT_FAILURE;
                          }
                   break;


        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) work = do_nothing;
                   break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_key_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;
   ak_libakrypt_set_password_read_function( aktool_key_load_user_password );

 /* теперь вызов соответствующей функции */
   switch( work ) {
     case do_new:
       exit_status = aktool_key_new();
       break;

     case do_show:
       if(( exit_status = aktool_key_show_key( )) == EXIT_FAILURE )
         aktool_error(_("using the file %s that does not contain correct "
                                                "secret or public key information"), ki.key_file );
       break;

     default:
       exit_status = EXIT_FAILURE;
   }

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new( void )
{
 /* сперва проверяем случаи, в которых генерация ключа отлична от обычной процедуры
    и требует дополнительных алгоритмических мер */
   if( ki.method != NULL ) {
     switch( ki.method->engine ) {
      case blom_master: return aktool_key_new_blom_master();
      case blom_subscriber: return aktool_key_new_blom_subscriber();
      case blom_pairwise: return aktool_key_new_blom_pairwise();

      default: aktool_error(_("the string %s (%s) is an identifier of %s which "
                                                    "does not used as key generation algorithm"),
          ki.method->name[0], ki.method->id[0], ak_libakrypt_get_engine_name( ki.method->engine ));
     }
     return EXIT_FAILURE;
   }

 /* теперь реализуем обычную процедуру, состоящую из генерации случайного вектора с помощью
    заданного генератора,
    начинаем с проверки входных данных */
   if( ki.oid_of_target == NULL ) {
     aktool_error(_("use --target option and set the name or identifier "
                                                      "of cryptographic algorithm for a new key"));
     return EXIT_FAILURE;
   }

  /* запускаем процедуру генерации ключа или ключевой пары */
   switch( ki.oid_of_target->engine ) {
    case block_cipher:
    case hmac_function:
      return aktool_key_new_keypair( ak_true, ak_false );

    case sign_function: /* создаем пару ключей */
      return aktool_key_new_keypair( ak_true, ak_true );

    default: aktool_error(_("the string %s (%s) is an identifier of %s which "
                                                             "does not use a cryptographic key"),
                                              ki.oid_of_target->name[0], ki.oid_of_target->id[0],
                                        ak_libakrypt_get_engine_name( ki.oid_of_target->engine ));
      return EXIT_FAILURE;
   }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_blom_master( void )
{
  struct blomkey master;
  int exitcode = EXIT_FAILURE;
  ak_pointer generator = NULL;

 /* формируем генератор случайных чисел */
  if( ki.name_of_file_for_generator != NULL ) {
    if( ak_random_create_file( generator = malloc( sizeof( struct random )),
                                                ki.name_of_file_for_generator ) != ak_error_ok ) {
      if( generator ) free( generator );
      return exitcode;
    }
    if( aktool_verbose ) printf(_("used a file with random data: %s\n"),
                                                                   ki.name_of_file_for_generator );
  }
   else {
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return exitcode;
    if( aktool_verbose ) printf(_("used a random number generator: %s\n"),
                                                                    ki.oid_of_generator->name[0] );
   }

  if( aktool_verbose ) {
    printf(_("    field: GF(2^%u)\n"), ki.field << 3 );
    printf(_("     size: %ux%u\n  process: "), ki.size, ki.size );
    fflush( stdout );
  }

 /* вырабатываем ключ заданного размера */
  if( ak_blomkey_create_matrix( &master, ki.size, ki.field, generator ) != ak_error_ok ) {
    aktool_error(_("incorrect master key generation"));
    goto labex;
  }
  if( aktool_verbose ) { printf(_("Ok\n\n")); }

 /* запрашиваем пароль для сохраняемых данных */
  if( !ki.lenpass  ) {
    if(( ki.lenpass = aktool_key_load_user_password_twice( ki.password, sizeof( ki.password ))) < 1 )
      goto labex1;
  }
 /* сохраняем созданный ключ в файле */
  if( ak_blomkey_export_to_file_with_password(
          &master,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file )
    ) != ak_error_ok )
      aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }

 labex1:
  ak_blomkey_destroy( &master );

 labex:
  if( ki.name_of_file_for_generator != NULL ) {
    ak_random_destroy( generator );
    free( generator );
  }
   else ak_oid_delete_object( ki.oid_of_generator, generator );

 /* очищаем память */
  memset( &ki, 0, sizeof( struct key_info ));
 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_blom_subscriber( void )
{
  int exitcode = EXIT_FAILURE;
  struct blomkey master, abonent;

 /* проверяем наличие имени пользователя */
  if( ki.lenuser == 0 ) {
    aktool_error(_("user or subscriber's name is undefined, use \"--id\" option" ));
    return exitcode;
  }
  if( strlen( ki.key_file ) == 0 ) {
    aktool_error(_("the file with master key is undefined, use \"--key\" option" ));
    return exitcode;
  }
 /* запрашиваем пароль для доступа к мастер ключу (однократно, без дублирования) */
  printf(_("loading master key: %s\n"), ki.key_file );
  if( ki.lenkeypass == 0 ) {
    if(( ki.lenkeypass = aktool_key_load_user_password( ki.key_password,
                                                               sizeof( ki.key_password ))) < 1 ) {
       aktool_error(_("incorrect password reading"));
       return exitcode;
    }
  }

 /* считываем ключ из заданного файла
    если пароль определен в командой строке, то используем именно его */
  if( ak_blomkey_import_from_file_with_password( &master,
                                  ki.key_password, ki.lenkeypass, ki.key_file ) != ak_error_ok ) {
    aktool_error(_("incorrect loading a master key from %s file\n"), ki.key_file );
    return exitcode;
  }
 /* создаем ключ абонента */
  if( strlen( ki.user ) == (size_t) ki.lenuser )
    printf(_("generation a %s key for %s: "), ki.method->name[0], ki.user );
   else printf(_("generation a %s key for %s: "), ki.method->name[0],
                                                ak_ptr_to_hexstr( ki.user, ki.lenuser, ak_false ));
  fflush( stdout );

  if( ak_blomkey_create_abonent_key( &abonent, &master, ki.user, ki.lenuser ) != ak_error_ok ) {
    aktool_error(_("incorrect creation of the abonent's key"));
    goto labex1;
  }
  printf(_("Ok\n\n"));

 /* запрашиваем пароль для сохранения ключа абонента */
  if( !ki.lenpass  ) {
    if(( ki.lenpass = aktool_key_load_user_password_twice( ki.password, sizeof( ki.password ))) < 1 )
      goto labex2;
  }

 /* сохраняем созданный ключ в файле */
  if( ak_blomkey_export_to_file_with_password(
          &abonent,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file )
    ) != ak_error_ok )
      aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }

 labex2:
   ak_blomkey_destroy( &abonent );
 labex1:
   ak_blomkey_destroy( &master );

 /* очищаем память */
  memset( &ki, 0, sizeof( struct key_info ));
 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/* создаем имя для ключа парной связи */
 static void aktool_key_new_blom_pairwise_keyname( void )
{
  time_t atime;
  struct hash ctx;
  ak_uint8 buffer[64];

 /* вырабатываем случайное имя файла */
   memset( buffer, 0, sizeof( buffer ));
   memcpy( buffer, ki.user, ak_min( (size_t) ki.lenuser, sizeof( buffer )));
   atime = time( NULL );
   memcpy( buffer + ( sizeof( buffer ) - sizeof( time_t )), &atime, sizeof( time_t ));
   ak_hash_create_streebog512( &ctx );
   ak_hash_ptr( &ctx, buffer, sizeof( buffer ), buffer, sizeof( buffer ));
   ak_hash_destroy( &ctx );
   ak_snprintf( ki.os_file, sizeof( ki.os_file ),
                                       "%s-pairwise.key", ak_ptr_to_hexstr( buffer, 8, ak_false ));
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_blom_pairwise( void )
{
  struct blomkey abonent;
  int exitcode = EXIT_FAILURE;

 /* проверяем наличие имени пользователя */
  if( ki.lenuser == 0 ) {
    aktool_error(_("user or subscriber's name is undefined, use \"--id\" option" ));
    return exitcode;
  }
 /* проверяем наличие файла с ключом пользователя */
  if( strlen( ki.key_file ) == 0 ) {
    aktool_error(_("the file with subscriber's key is undefined, use \"--key\" option" ));
    return exitcode;
  }
 /* проверяем, что алгоритм для нового ключа парной связи определен */
  if( ki.target_undefined == ak_false ) {
    if( ki.oid_of_target == NULL ) {
      aktool_error(_("the target cryptographic algorithm for pairwise key is undefined,"
                                                                     " use \"--target\" option" ));
      return exitcode;
    }
    switch( ki.oid_of_target->engine ) {
      case block_cipher:
      case hmac_function:
      case sign_function:
        break;

      default:
        aktool_error(_("an engine of the given target cryptographic"
                                                             " algorithm is not supported (%s)" ),
                                         ak_libakrypt_get_engine_name( ki.oid_of_target->engine ));
        return exitcode;
    }
  }

 /* запрашиваем пароль для доступа к ключу абонента (однократно, без дублирования) */
  printf(_("loading subscriber's key: %s\n"), ki.key_file );
  if( ki.lenkeypass == 0 ) {
    if(( ki.lenkeypass = aktool_key_load_user_password( ki.key_password,
                                                               sizeof( ki.key_password ))) < 1 ) {
       aktool_error(_("incorrect password reading"));
       return exitcode;
    }
  }
 /* считываем ключ из заданного файла
    если пароль определен в командой строке, то используем именно его */
  if( ak_blomkey_import_from_file_with_password( &abonent,
                                  ki.key_password, ki.lenkeypass, ki.key_file ) != ak_error_ok ) {
    aktool_error(_("incorrect loading an abonent key from %s file\n"), ki.key_file );
    return exitcode;
  }
 /* создаем ключ парной связи */
  if( strlen( ki.user ) == (size_t) ki.lenuser )
    printf(_("generation a pairwise key for %s: "), ki.user );
   else printf(_("generation a pairwise key for %s: "),
                                                ak_ptr_to_hexstr( ki.user, ki.lenuser, ak_false ));
  fflush( stdout );

  if( ki.target_undefined == ak_true ) { /* вырабатываем незашированный вектор */
    struct file fs;
    ak_uint8 key[64];

    if( ak_blomkey_create_pairwise_key_as_ptr( &abonent,
                                      ki.user, ki.lenuser, key, abonent.count ) != ak_error_ok ) {
      aktool_error(_("wrong pairwise key generation"));
      goto labex1;
    }
    printf(_("Ok\n\n"));
    if( strlen( ki.os_file ) == 0 ) aktool_key_new_blom_pairwise_keyname();
    if( ak_file_create_to_write( &fs, ki.os_file ) != ak_error_ok ) {
      aktool_error(_("incorrect key file creation"));
      goto labex1;
    }
    if( ak_file_write( &fs, key, abonent.count ) != abonent.count ) {
      aktool_error(_("incorrect write to %s%s%s file"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
    }
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }
    ak_file_close( &fs );
  } /* конец генерации undefined key */

   else { /* вырабатываем секретный ключ для заданного опцией --target алгоритма */
     time_t now = time( NULL ), after = now + ki.days*86400;
     ak_pointer key = NULL;
     if(( key = ak_blomkey_new_pairwise_key( &abonent, ki.user, ki.lenuser,
                                                                   ki.oid_of_target )) == NULL ) {
      aktool_error(_("wrong pairwise key generation"));
      goto labex1;
     }
     printf(_("Ok\n\n"));

    if( aktool_verbose ) printf(_("new key information:\n"));
    /* вот еще что надо бы не забыть - метку */
     if( strlen( ki.keylabel ) != 0 ) {
       if( aktool_verbose ) printf(_("%2clabel = %s\n"), ' ', ki.keylabel );
       ak_skey_set_label( (ak_skey)key, ki.keylabel, 0 );
     }
   /* устанавливаем срок действия, в сутках, начиная с текущего момента */
     if( aktool_verbose ) {
       printf(_("  resource = %lld "), (long long int)((ak_skey)key)->resource.value.counter );
       if( ((ak_skey)key)->resource.value.type == block_counter_resource ) printf(_("blocks\n"));
        else  printf(_("usages\n"));
       printf(_("  not before = %s"), ctime( &now ));
       printf(_("  not after = %s"), ctime( &after ));
     }
     if( ak_skey_set_validity( (ak_skey)key, now, after ) != ak_error_ok ) {
       aktool_error(_("incorrect assigning the validity of secret key"));
       goto labex1;
     }

    /* запрашиваем пароль для сохранения ключа абонента */
     if( ki.lenpass == 0 ) {
       if(( ki.lenpass =
                   aktool_key_load_user_password_twice( ki.password, sizeof( ki.password ))) < 1 )
         goto labex2;
     }

   /* теперь экпортируем ключ */
     if( ak_skey_export_to_file_with_password(
          key,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
         ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
          ki.format
       ) != ak_error_ok ) aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }
     labex2: ak_oid_delete_object( ki.oid_of_target, key );
  }

 labex1:
   ak_blomkey_destroy( &abonent );

 /* очищаем память */
  memset( &ki, 0, sizeof( struct key_info ));
 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- *
 \param create_secret флаг должен установлен для создания секретного ключа
 \param create_pair флаг должен быть установлен для генерации пары асимметричных ключей
 * ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_keypair( bool_t create_secret , bool_t create_pair )
{
  time_t now = time( NULL );
  int exitcode = EXIT_FAILURE;
  ak_pointer key = NULL, generator = NULL;

  if( !create_secret ) return EXIT_FAILURE;
 /* формируем генератор случайных чисел */
  if( ki.name_of_file_for_generator != NULL ) {
    if( ak_random_create_file( generator = malloc( sizeof( struct random )),
                                                ki.name_of_file_for_generator ) != ak_error_ok ) {
      if( generator ) free( generator );
      return exitcode;
    }
    if( aktool_verbose ) printf(_("used a file with random data: %s\n"),
                                                                   ki.name_of_file_for_generator );
  }
   else {
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return exitcode;
    if( aktool_verbose ) printf(_("used a random number generator: %s\n"),
                                                                    ki.oid_of_generator->name[0] );
   }

 /* создаем ключ */
  if(( key = ak_oid_new_object( ki.oid_of_target )) == NULL ) goto labex;

 /* для асимметричных ключей устанавливаем кривую */
  if( ki.oid_of_target->engine == sign_function ) {
    if( ak_signkey_set_curve( key, ki.curve->data ) != ak_error_ok ) {
      aktool_error(_("using non applicable elliptic curve (%s)"), ki.curve->name[0] );
      goto labex2;
    }
  }

 /* вырабатываем случайный секретный ключ */
  if( ki.oid_of_target->func.first.set_key_random( key, generator ) != ak_error_ok ) {
    aktool_error(_("incorrect creation of a random secret key value"));
    goto labex2;
  }

 /* устанавливаем срок действия, в сутках, начиная с текущего момента */
  if( ak_skey_set_validity( key, now, now + ki.days*86400 ) != ak_error_ok ) {
    aktool_error(_("incorrect assigning the validity of secret key"));
    goto labex2;
  }

 /* устанавливаем метку */
  if( strlen( ki.keylabel ) > 0 ) {
    if( ak_skey_set_label( key, ki.keylabel, strlen( ki.keylabel )) != ak_error_ok ) {
      aktool_error(_("incorrect assigning the label of secret key"));
      goto labex2;
    }
  }

 /* !!! переходим к открытому ключу !!! */
 /* далее, мы создаем запрос на сертификат открытого ключа или
    самоподписаный сертификат открытого ключа */
  if( create_pair ) { /* телодвижения для асимметричных ключей */
    struct verifykey vkey;

   /* вырабатываем открытый ключ,
      это позволяет выработать номер открытого ключа, а также присвоить ему имя и ресурс */
    if( ak_verifykey_create_from_signkey( &vkey, key ) != ak_error_ok ) {
      aktool_error(_("incorrect creation of public key"));
      goto labex2;
    }
   /* создаем обобщенное имя владельца ключей */
    if( aktool_key_input_name( &vkey ) != ak_error_ok ) {
      aktool_error(_("incorrect creation of owner's distinguished name"));
      goto labex2;
    }

    if( ki.format == aktool_magic_number ) { /* сохраняем открытый ключ как корневой сертификат */

     /* для корневого (самоподписанного) сертификата обязательно устанавливаем бит keyCertSign */
      ki.opts.key_usage.is_present = ak_true;
      if(( ki.opts.key_usage.bits&bit_keyCertSign ) == 0 ) {
        ki.opts.key_usage.bits = ( ki.opts.key_usage.bits&(~bit_keyCertSign ))^bit_keyCertSign;
      }

      ki.format = asn1_pem_format; /* возвращаем необходимое значение */
      if( ak_verifykey_export_to_certificate( &vkey, key, &vkey, generator,  &ki.opts,
                          ki.op_file, ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ),
                                                                     ki.format ) != ak_error_ok ) {
        aktool_error(_("wrong export a public key to certificate %s%s%s"),
                              ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
        goto labex2;
      }
       else printf(_("certificate of public key stored in %s%s%s file\n\n"),
                              ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
    }
     else { /* сохраняем запрос на сертификат */
        if( ak_verifykey_export_to_request( &vkey, key, generator, ki.op_file,
           ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ), ki.format ) != ak_error_ok ) {
          aktool_error(_("wrong export a public key to request %s%s%s"),
                              ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
          goto labex2;
        } else
            printf(_("public key stored in %s%s%s file as certificate's request\n\n"),
                              ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
     }

    ak_verifykey_destroy( &vkey );
  } /* конец if( create_pair ) */

 /* мастерим пароль для сохранения секретного ключа */
  if( ki.lenpass == 0 ) {
    if(( ki.lenpass = aktool_key_load_user_password_twice( ki.password, sizeof( ki.password ))) < 1 )
    goto labex2;
  }

 /* сохраняем созданный ключ в файле */
  if( ak_skey_export_to_file_with_password(
          key,             /* ключ */
          ki.password,     /* пароль */
          ki.lenpass,      /* длина пароля */
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
          ki.format
     ) != ak_error_ok ) {
     aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     goto labex2;
  } else {
     /* секретный ключ хорошо хранить в хранилище */
     printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
    }

 /* удаляем память */
  labex2:
   ak_oid_delete_object( ki.oid_of_target, key );

  labex:
   if( ki.name_of_file_for_generator != NULL ) {
     ak_random_destroy( generator );
     free( generator );
   }
    else ak_oid_delete_object( ki.oid_of_generator, generator );

 /* очищаем память */
  memset( &ki, 0, sizeof( struct key_info ));
 return exitcode;
}


/* ----------------------------------------------------------------------------------------------- */
 static int aktool_key_input_name_from_console_line( ak_verifykey key,
                                                                 const char *sh, const char *lg  )
{
  size_t len = 0;
  char string[256];
  char *ptr = NULL;
  int error = ak_error_not_ready;

  if(( ptr = strstr( ki.user, sh )) != NULL ) {
    ptr+=3;
    len = 0;
    while( len < strlen( ptr )) {
      if( ptr[len]   == '/') break;
      ++len;
    }
    if( len > 0 ) {
      memset( string, 0, sizeof( string ));
      memcpy( string, ptr, len );
      error = ak_verifykey_add_name_string( key, lg, string );
    }
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/* в короткой форме мы поддерживаем флаги /cn/su/sn/ct/ln/st/or/ou/em (передается через --id)      */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_input_name_from_console( ak_verifykey key )
{
  int error = ak_error_ok, found = ak_false;

  if( aktool_key_input_name_from_console_line( key,
                                         "/em", "email-address" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                           "/cn", "common-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                               "/su", "surname" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                         "/sn", "serial-number" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                          "/ct", "country-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                         "/lt", "locality-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                "/st", "state-or-province-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                        "/sa", "street-address" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                          "/or", "organization" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                     "/ou", "organization-unit" ) == ak_error_ok ) found = ak_true;
  if( !found ) {
    error = ak_verifykey_add_name_string( key, "common-name", ki.user );
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_input_name( ak_verifykey key )
{
  size_t len = 0;
  char string[256];
  bool_t noname = ak_true;

 /* a. Проверяем, задана ли строка с расширенным именем владельца */
  if( ki.lenuser > 0 ) return aktool_key_input_name_from_console( key );

 /* b. Выводим стандартное пояснение */
  printf(_(" -----\n"
   " You are about to be asked to enter information that will be incorporated\n"
   " into your certificate request.\n"
   " What you are about to enter is what is called a Distinguished Name or a DN.\n"
   " There are quite a few fields but you can leave some blank.\n"
   " For some fields there will be a default value.\n"
   " If you do not want to provide information just enter a string of one or more spaces.\n"
   " -----\n"));

 /* Вводим расширенное имя с клавиатуры
    1. Country Name */

  ak_snprintf( string, len = sizeof( string ), "RU" );
  if( ak_string_read(_("Country Name (2 letter code)"), string, &len ) == ak_error_ok ) {
   #ifdef AK_HAVE_CTYPE_H
    string[0] = toupper( string[0] );
    string[1] = toupper( string[1] );
   #endif
    string[2] = 0;
    if( len && ( ak_verifykey_add_name_string( key,
                                      "country-name", string ) == ak_error_ok )) noname = ak_false;
  }
 /* 2. State or Province */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("State or Province"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                            "state-or-province-name", string ) == ak_error_ok )) noname = ak_false;
 /* 3. Locality */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Locality (eg, city)"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                     "locality-name", string ) == ak_error_ok )) noname = ak_false;
 /* 4. Organization */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization (eg, company)"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                      "organization", string ) == ak_error_ok )) noname = ak_false;
 /* 5. Organization Unit*/
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization Unit"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                 "organization-unit", string ) == ak_error_ok )) noname = ak_false;
 /* 6. Street Address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Street Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                    "street-address", string ) == ak_error_ok )) noname = ak_false;
 /* 7. Common Name */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Common Name"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                       "common-name", string ) == ak_error_ok )) noname = ak_false;
 /* 8. email address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Email Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                     "email-address", string ) == ak_error_ok )) noname = ak_false;
  if( noname ) {
    aktool_error(
   _("generation of a secret or public keys without any information about owner are not allowed"));
    return ak_error_invalid_value;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_show_key( void )
{
  if( aktool_key_show_secret_key() == EXIT_SUCCESS ) return EXIT_SUCCESS;
  if( aktool_key_show_public_key() == EXIT_SUCCESS ) return EXIT_SUCCESS;

 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_show_secret_key( void )
{
 /* создаем контекст ключа (без считывания ключевой информации, только параметры) */
  ak_pointer key = ak_skey_new_from_file( ki.key_file );
  ak_skey skey = (ak_skey)key;
  if( key == NULL ) return EXIT_FAILURE;

  printf(_("type:\n    "));
  if( skey->oid->engine == sign_function ) printf(_("asymmetric secret key\n"));
   else printf(_("symmetric secret key\n"));
  printf(_("algorithm:\n    %s (%s, %s)\n"), ak_libakrypt_get_engine_name( skey->oid->engine ),
                                                            skey->oid->name[0], skey->oid->id[0] );
  printf(_("number:\n    %s\n"), ak_ptr_to_hexstr( skey->number, 32, ak_false ));
  printf(_("resource:\n    %s: %ld\n"),
                               ak_libakrypt_get_counter_resource_name( skey->resource.value.type ),
                                                       (long int)( skey->resource.value.counter ));
  printf(_("    not before: %s"), ctime( &skey->resource.time.not_before ));
  printf(_("    not after:  %s"), ctime( &skey->resource.time.not_after ));

 /* для асимметричных секретных ключей выводим дополнительную информацию */
  if( skey->oid->engine == sign_function ) {
    ak_uint8 zerobuf[32];
    ak_oid curvoid = ak_oid_find_by_data( skey->data );

    printf(_("public key number:\n"));
    memset( zerobuf, 0, sizeof( zerobuf ));
    if( memcmp( zerobuf, ((ak_signkey)key)->verifykey_number, 32 ) == 0 )
      printf(_("( undefined )\n"));
     else printf("    %s\n", ak_ptr_to_hexstr(((ak_signkey)key)->verifykey_number, 32, ak_false ));

    printf(_("elliptic curve:\n"));
    if( curvoid == NULL ) printf(_("( undefined )\n"));
      else printf("    %s (%s)\n", curvoid->name[0], curvoid->id[0] );
  }

  if( skey->label != NULL ) printf(_("label:\n    %s\n"), skey->label );
  printf(_("file:\n    %s\n"), ki.key_file );

  ak_oid_delete_object( ((ak_skey)key)->oid, key );
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_show_public_key( void )
{
  struct verifykey vkey;
  int error = ak_error_ok, exitcode = EXIT_FAILURE;

 /* сначала тестируем запрос на сертификат */
  if(( error = ak_verifykey_import_from_request( &vkey,
                                          ki.key_file, aktool_certificate_out )) == ak_error_ok ) {
    ak_verifykey_destroy( &vkey );
    exitcode = EXIT_SUCCESS;
    goto labex;
  }

// /* проверяем, что ошибка не в контроле целостности */
//  if( ak_error_get_value() == ak_error_not_equal_data ) {
//    aktool_error(_("wrong verification of request's signature"));
//    goto labex2;
//  }
// /* и тестируем собственно сертификат открытого ключа */


////     // printf(_("      type: public key's certificate\n"));
////     // content = public_key_certificate_content;

////    printf("%d\n", ak_error_get_value());

////  }

//  labex:
// /* теперь выводим информацию о считанном открытом ключе */
//  if( exitcode == EXIT_SUCCESS ) {
//    ak_oid curvoid = ak_oid_find_by_data( vkey->wc );
//    printf(_(" algorithm: %s (%s, %s)\n"), ak_libakrypt_get_engine_name( vkey->oid->engine ),
//                                                            vkey->oid->name[0], vkey->oid->id[0] );
//    printf("    key.px: %s\n", ak_mpzn_to_hexstr( vkey->qpoint.x, vkey->wc->size ));
//    printf("    key.py: %s\n", ak_mpzn_to_hexstr( vkey->qpoint.y, vkey->wc->size ));
//    printf(_("    number: %s\n"), ak_ptr_to_hexstr( vkey->number, 32, ak_false ));
//    printf(_("     curve: "));
//    if( curvoid ) printf("%s (%s)\n", curvoid->name[0], curvoid->id[0] );
//      else printf(_("( undefined )\n"));

//   /* вывод информации о владельце ключа */
//    printf(_("     owner:"));
//    if( vkey->name == NULL ) printf(_("( undefined )\n"));
//     else {
//      ak_tlv_print_global_name( vkey->name, stdout );
//      printf("\n");
//     }
//   /* срок действия оределяется в момент создания сертификата */
//    if( content == public_key_certificate_content ) {
//      printf(_("not before: %s"), ctime( &vkey->time.not_before ));
//      printf(_(" not after: %s"), ctime( &vkey->time.not_after ));
//    }
//    printf(_("    verify: Ok\n"));
//    printf(_("      file: %s\n"), ki.key_file );
//    ak_verifykey_destroy( vkey );
//    free( vkey );
//  }

  labex:
 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
// СДЕЛАТЬ -c <request> с параметром, а опцию --req удалить
//     " -c, --cert              create a public key certificate from a given request\n"

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void )
{
  printf(
   _("aktool key [options]  - key generation and management functions\n\n"
     "available options:\n"
     " -a, --algorithm         specify the method or the cryptographic algorithm for key generation\n"
     "                         this option needs to be used in some key generation schemes, e.g. in Blom scheme\n"
     "     --curve             set the elliptic curve name or identifier for asymmetric keys\n"
     "     --days              set the days count to expiration date of secret or public key\n"
     "     --field             bit length which used to define the galois field [ enabled values: 256, 512 ]\n"
     "     --format            set the format of output file [ enabled values: der, pem, certificate ]\n"
     "     --hexid             set a user or suscriber's identifier as hexademal string\n"
     "     --hexpass           specify the password directly in command line as hexademal string\n"
     "     --id                set a generalized name or identifier for the user, subscriber or key owner\n"
     "                         if the identifier contains control commands, it is interpreted as a set of names\n"
     "     --key               specify the name of file with the secret key\n"
     "                         this can be a master key or issuer's key which is used to sign a certificate\n"
     "     --key-hexpass       set the password for the secret key to be read directly in command line as hexademal string\n"
     "     --key-password      set the password for the secret key to be read directly in command line\n"
     "     --label             assign the user-defined label to secret key\n"
     " -n, --new               generate a new key or key pair for specified target\n"
     "     --op                short form of --output-public-key option\n"
     "     --output-public-key set the file name for the new public key request\n"
     " -o, --output-secret-key set the file name for the new secret key\n"
     "     --password          specify the password for storing a secret key directly in command line\n"
     "     --pubkey            name of the issuer's public key, information from which will be placed in the certificate\n"
     "     --random            set the name or identifier of random sequences generator\n"
     "                         the generator will be used to create a new key [ default value: \"%s\" ]\n"
     "     --random-file       set the name of file with random sequence\n"
     " -s, --show              output the parameters of the secret key (symmetric or asymmetric)\n"
     "     --size              set the dimension of secret master key in blom scheme [ maximal value: 4096 ]\n"
     " -t, --target            specify the name of the cryptographic algorithm for the new generated key\n"
     "                         one can use any supported names or identifiers of algorithm,\n"
     "                         or \"undefined\" value for generation the plain unecrypted key unrelated to any algorithm\n"
     "     --to                another form of --format option\n\n"
     "options used for customizing a public key's certificate:\n"
     "     --authority-keyid   add an authority key identifier to certificate being created\n"
     "                         this option should only be used for self-signed certificates,\n"
     "                         in other cases it is used by default\n"
     "     --authority-name    add an issuer's generalized name to the authority key identifier extension\n"
     "     --ca                use as certificate authority [ enabled values: true, false ]\n"
     "     --pathlen           set the maximal length of certificate's chain\n"
     "     --digital-signature use for verifying a digital signatures of user data\n"
     "     --content-commitment\n"
     "     --key-encipherment  use for encipherment of secret keys\n"
     "     --data-encipherment use for encipherment of user data (is not usally used)\n"
     "     --key-agreement     use in key agreement protocols for subject's authentication\n"
     "     --key-cert-sign     use for verifying of public key's certificates\n"
     "     --crl-sign          use for verifying of revocation lists of certificates\n"
  ),
  aktool_default_generator
 );
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   aktool_key.c  */
/* ----------------------------------------------------------------------------------------------- */
