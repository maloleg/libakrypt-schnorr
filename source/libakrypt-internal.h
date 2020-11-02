/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл libakrypt-internal.h                                                                      */
/*   - содержит заголовки неэкспортируемых функций                                                 */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_INTERNAL_H__
#define    __LIBAKRYPT_INTERNAL_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey Cекретные ключи криптографических механизмов
 @{ */
/*! \brief Инициализация секретного ключа алгоритма блочного шифрования. */
 int ak_bckey_create( ak_bckey , size_t , size_t );
/*! \brief Инициализация ключа алгоритма блочного шифрования значением другого ключа */
 int ak_bckey_create_and_set_bckey( ak_bckey , ak_bckey );
/*! \brief Процедура вычисления производного ключа в соответствии с алгоритмом ACPKM
    из рекомендаций Р 1323565.1.012-2018. */
 int ak_bckey_next_acpkm_key( ak_bckey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Выработка матрицы, соответствующей 16 тактам работы линейного региста сдвига. */
 void ak_bckey_kuznechik_generate_matrix( const linear_register , linear_matrix );
/*! \brief Обращение сопровождающей матрицы. */
 void ak_bckey_kuznechik_invert_matrix( linear_matrix , linear_matrix );
/*! \brief Обращение таблицы нелинейного преобразования. */
 void ak_bckey_kuznechik_invert_permutation( const sbox , sbox );
/*! \brief Инициализация внутренних структур данных, используемых при реализации алгоритма
    блочного шифрования Кузнечик (ГОСТ Р 34.12-2015). */
 int ak_bckey_kuznechik_init_tables( const linear_register ,
                                                                const sbox , ak_kuznechik_params );
/*! \brief Инициализация внутренних переменных значениями, регламентируемыми ГОСТ Р 34.12-2015. */
 int ak_bckey_kuznechik_init_gost_tables( void );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mac Вычисление кодов целостности (хеширование и имитозащита)
 @{ */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализации контекста начальными значениями. */
 int ak_mac_create( ak_mac , const size_t , ak_pointer ,
     ak_function_context_clean * , ak_function_context_update * , ak_function_context_finalize * );
/*! \brief Функция удаления контекста. */
 int ak_mac_destroy( ak_mac );
/*! \brief Очистка контекста сжимающего отображения. */
 int ak_mac_clean( ak_mac );
/*! \brief Обновление состояния контекста сжимающего отображения. */
 int ak_mac_update( ak_mac , const ak_pointer , const size_t );
/*! \brief Обновление состояния и вычисление результата применения сжимающего отображения. */
 int ak_mac_finalize( ak_mac , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Применение сжимающего отображения к заданной области памяти. */
 int ak_mac_ptr( ak_mac , ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Применение сжимающего отображения к заданному файлу. */
 int ak_mac_file( ak_mac , const char* , ak_pointer , const size_t );
/** @} */

/** \addtogroup aead
 @{ */
 #define ak_aead_assosiated_data_bit  (0x1)
 #define ak_aead_encrypted_data_bit   (0x2)

 #define ak_aead_set_bit( x, n ) ( (x) = ((x)&(0xFFFFFFFF^(n)))^(n) )
/** @} */

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                            libakrypt-internal.h */
/* ----------------------------------------------------------------------------------------------- */
