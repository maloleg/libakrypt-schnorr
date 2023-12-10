 #include <libakrypt-internal.h>

 void ak_signkey_sign_const_values_schnorr( ak_signkey sctx, ak_uint64 *k, ak_uint64 *e, ak_pointer out, ak_uint8* hash_out)
{
  struct hash ctx; /* контекст функции хеширования */
  int error = ak_error_ok;
  int audit = ak_log_get_level();

  ak_mpzn512 r, s;
  ak_mpzn512 x, y, z;
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;

 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );

  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

  ak_mpzn_rem(x, wr.x, wc->q, wc->size );
  ak_mpzn_rem(y, wr.y, wc->q, wc->size );
  ak_mpzn_rem(z, wr.z, wc->q, wc->size );

 /* приводим r к виду Монтгомери и помещаем во временную переменную wr.x <- r */
  ak_mpzn_mul_montgomery( wr.x, r, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем значение s <- r*d (mod q) (сначала домножаем на ключ, потом на его маску) */
  ak_mpzn_mul_montgomery( s, wr.x, (ak_uint64 *)sctx->key.key, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( s, s,
              (ak_uint64 *)(sctx->key.key+sctx->key.key_size), wc->q, wc->nq, wc->size );

 /* приводим k к виду Монтгомери и помещаем во временную переменную wr.y <- k */
  ak_mpzn_mul_montgomery( wr.y, k, wc->r2q, wc->q, wc->nq, wc->size );

 /* приводим e к виду Монтгомери и помещаем во временную переменную wr.z <- e */
  ak_mpzn_rem( wr.z, e, wc->q, wc->size );
  if( ak_mpzn_cmp_ui( wr.z, wc->size, 0 )) ak_mpzn_set_ui( wr.z, wc->size, 1 );
  ak_mpzn_mul_montgomery( wr.z, wr.z, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем k*e (mod q) и вычисляем s = r*d + k (mod q) (в форме Монтгомери) */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

  // посчитать хэш от s||C:
  ak_uint64 *concatenate_s_c = malloc((ak_mpzn256_size*3 + ak_mpzn256_size) * sizeof(ak_uint64));

  memcpy(concatenate_s_c, e, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size) / 8, x, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*2) / 8, y, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*3) / 8, z, ak_mpzn256_size * sizeof(ak_uint64));
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
    exit(-1);
  }
 /* первый пример из приложения А (ГОСТ Р 34.11-2012) */

  ak_hash_ptr( &ctx, concatenate_s_c, sizeof(concatenate_s_c) * 16, hash_out, sizeof( hash_out ) * 4);

  free(concatenate_s_c);


  printf("\n HASH FROM SIGNATURE:\n");
  for (size_t i = 0; i < 32; i++){
    printf("0x%x ", hash_out[i]);
  }

  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    // return ak_false;
    exit(-1);
  }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "hash streebog is Ok" );

 /* приводим s к обычной форме */
  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
 /* экспортируем результат*/
  ak_mpzn_to_little_endian( s, wc->size, out, sizeof(ak_uint64)*wc->size, ak_true );
  ak_mpzn_to_little_endian( r, wc->size, (ak_uint64 *)out + wc->size, sizeof(ak_uint64)*wc->size, ak_true );
 /* завершаемся */

  memset( &wr, 0, sizeof( struct wpoint ));
  sctx->key.set_mask( &sctx->key );
  memset( r, 0, sizeof( ak_mpzn512 ));
  memset( s, 0, sizeof( ak_mpzn512 ));

}


int ak_signkey_sign_schnorr( ak_signkey sctx, ak_uint64 *k, ak_uint64 *e, ak_pointer out, ak_uint8* hash_out)
{

  struct hash ctx; /* контекст функции хеширования */
  int error = ak_error_ok;
  int audit = ak_log_get_level();

  ak_mpzn512 r, s;
  ak_mpzn512 x, y, z;
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;

 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );

  

  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

  ak_mpzn_rem(x, wr.x, wc->q, wc->size );
  ak_mpzn_rem(y, wr.y, wc->q, wc->size );
  ak_mpzn_rem(z, wr.z, wc->q, wc->size );

 /* приводим r к виду Монтгомери и помещаем во временную переменную wr.x <- r */
  ak_mpzn_mul_montgomery( wr.x, r, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем значение s <- r*d (mod q) (сначала домножаем на ключ, потом на его маску) */
  ak_mpzn_mul_montgomery( s, wr.x, (ak_uint64 *)sctx->key.key, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( s, s,
              (ak_uint64 *)(sctx->key.key+sctx->key.key_size), wc->q, wc->nq, wc->size );

 /* приводим k к виду Монтгомери и помещаем во временную переменную wr.y <- k */
  ak_mpzn_mul_montgomery( wr.y, k, wc->r2q, wc->q, wc->nq, wc->size );

 /* приводим e к виду Монтгомери и помещаем во временную переменную wr.z <- e */
  ak_mpzn_rem( wr.z, e, wc->q, wc->size );
  if( ak_mpzn_cmp_ui( wr.z, wc->size, 0 )) ak_mpzn_set_ui( wr.z, wc->size, 1 );
  ak_mpzn_mul_montgomery( wr.z, wr.z, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем k*e (mod q) и вычисляем s = r*d + k (mod q) (в форме Монтгомери) */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

  // посчитать хэш от s||C:
  ak_uint64 *concatenate_s_c = malloc((ak_mpzn256_size*3 + ak_mpzn256_size) * sizeof(ak_uint64));

  memcpy(concatenate_s_c, e, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size) / 8, x, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*2) / 8, y, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*3) / 8, z, ak_mpzn256_size * sizeof(ak_uint64));
  
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
    exit(-1);
  }

  ak_hash_ptr( &ctx, concatenate_s_c, sizeof(concatenate_s_c) * 16, hash_out, sizeof( hash_out ) * 4);

  free(concatenate_s_c);


  printf("\n HASH FROM SIGNATURE:\n");
  for (size_t i = 0; i < 32; i++){
    printf("0x%x ", hash_out[i]);
  }

  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    exit(-1);
  }

  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "hash streebog is Ok" );

 /* приводим s к обычной форме */
  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
 /* экспортируем результат  + добавить экспорт хэша ебаного */
  ak_mpzn_to_little_endian( s, wc->size, out, sizeof(ak_uint64)*wc->size, ak_true );
  ak_mpzn_to_little_endian( r, wc->size, (ak_uint64 *)out + wc->size, sizeof(ak_uint64)*wc->size, ak_true );
 /* завершаемся */

  memset( &wr, 0, sizeof( struct wpoint ));
  sctx->key.set_mask( &sctx->key );
  memset( r, 0, sizeof( ak_mpzn512 ));
  memset( s, 0, sizeof( ak_mpzn512 ));

  return ak_true;
}


 bool_t ak_verifykey_verify_hash_schnorr( ak_verifykey pctx,
                                        const ak_pointer hash, const size_t hsize, ak_pointer sign)
{
#ifndef AK_LITTLE_ENDIAN
  int i = 0;
#endif

  struct hash ctx;
  int error = ak_error_ok;
  int audit = ak_log_get_level();


  ak_mpzn512 v, r, s, h;
  ak_mpzn512 x, y, z;
  struct wpoint cpoint, tpoint;
  ak_uint8 hash_out_new[64];

  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                               "using a null pointer to secret key context" );
    return ak_false;
  }
  if( hash == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hash value" );
    return ak_false;
  }
  if( hsize != sizeof( ak_uint64 )*(pctx->wc->size )) {
    ak_error_message( ak_error_wrong_length, __func__, "using hash value with wrong length" );
    return ak_false;
  }
  if( sign == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to sign value" );
    return ak_false;
  }
 /* импортируем подпись */
  ak_mpzn_set_little_endian( s, pctx->wc->size, sign, sizeof(ak_uint64)*pctx->wc->size, ak_true );
  ak_mpzn_set_little_endian( r, pctx->wc->size, ( ak_uint64* )sign + pctx->wc->size,
                                                      sizeof(ak_uint64)*pctx->wc->size, ak_true );



  memcpy( h, hash, sizeof( ak_uint64 )*pctx->wc->size );
#ifndef AK_LITTLE_ENDIAN
  for( i = 0; i < pctx->wc->size; i++ ) h[i] = bswap_64( h[i] );
#endif

  ak_mpzn_set( v, h, pctx->wc->size );
  ak_mpzn_rem( v, v, pctx->wc->q, pctx->wc->size );
  if( ak_mpzn_cmp_ui( v, pctx->wc->size, 0 )) ak_mpzn_set_ui( v, pctx->wc->size, 1 );
  ak_mpzn_mul_montgomery( v, v, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

 /* сложение точек и проверка */
  ak_wpoint_pow( &cpoint, &pctx->wc->point, s, pctx->wc->size, pctx->wc );
  ak_wpoint_pow( &tpoint, &pctx->qpoint, r, pctx->wc->size, pctx->wc );

  struct wpoint inverse_tpoint;
  ak_wpoint_set_wpoint( &inverse_tpoint, &tpoint,  pctx->wc );
  ak_mpzn_sub( inverse_tpoint.y,  pctx->wc->p, inverse_tpoint.y,  pctx->wc->size );
  ak_wpoint_add( &cpoint, &inverse_tpoint, pctx->wc );

  ak_wpoint_reduce( &cpoint, pctx->wc );

  ak_mpzn_rem(x, cpoint.x, pctx->wc->q, pctx->wc->size );
  ak_mpzn_rem(y, cpoint.y, pctx->wc->q, pctx->wc->size );
  ak_mpzn_rem(z, cpoint.z, pctx->wc->q, pctx->wc->size );
  
  ak_uint64 *concatenate_s_c = malloc((ak_mpzn256_size*3 + ak_mpzn256_size) * sizeof(ak_uint64));

  memcpy(concatenate_s_c, hash, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size) / 8, cpoint.x, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*2) / 8, cpoint.y, ak_mpzn256_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*3) / 8, cpoint.z, ak_mpzn256_size * sizeof(ak_uint64));
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
      exit(-1);
    }
    
    ak_hash_ptr( &ctx, concatenate_s_c, sizeof(concatenate_s_c) * 16, hash_out_new, sizeof( hash_out_new ) * 4);

    free(concatenate_s_c);

    if(( error = ak_error_get_value()) != ak_error_ok ) {
      ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
     return ak_false;
     }


     if( audit >= ak_log_maximum )
     ak_error_message( ak_error_ok, __func__ , "hash streebog is Ok" );

	 printf("\n RECOVERED HASH FROM SIGNATURE:\n");
     for (size_t i = 0; i < 32; i++){
    	printf("0x%x ", hash_out_new[i]);
     }

  if( ak_mpzn_cmp( cpoint.x, r, pctx->wc->size )) {
    ak_ptr_is_equal_with_log( cpoint.x, r, pctx->wc->size*sizeof( ak_uint64 ));
    return ak_false;
  }
 return ak_true;
}


 int ak_signkey_sign_file_schnorr( ak_signkey sctx, ak_uint64 *k, const char *filename,
                                                                   ak_pointer out, ak_uint8* hash_out)
{
  int error = ak_error_ok;
  ak_uint8 hash[256]; /* выбираем максимально возможный размер */

 /* необходимые проверки */
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to file name" );
  if( sctx->ctx.data.sctx.hsize > 64 ) return ak_error_message( ak_error_wrong_length,
                             __func__, "using hash function with very large hash code size" );

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, sizeof( hash ));
  if(( error = ak_hash_file( &sctx->ctx, filename, hash, sizeof( hash ))) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong calculation of hash value" );

 /* выработанный хеш-код представляет собой последовательность байт
    данная последовательность не зависит от используемой архитектуры используемой ЭВМ */
 return ak_signkey_sign_schnorr( sctx, k, (ak_uint64 *)hash, out, hash_out);
}

//int ak_signkey_sign_schnorr( ak_signkey sctx, ak_random generator, ak_uint64 *e, ak_pointer out, ak_uint8* hash_out)

bool_t ak_verifykey_verify_file_schnorr( ak_verifykey pctx, const char *filename, ak_pointer sign )
{
  ak_uint8 hash[256];
  int error = ak_error_ok;

 /* необходимые проверки */
  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return ak_false;
  }
  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
    return ak_false;
  }
  if( pctx->ctx.data.sctx.hsize > sizeof( hash )) {
    ak_error_message( ak_error_wrong_length, __func__,
                                            "using hash function with large hash code size" );
    return ak_false;
  }
  memset( hash, 0, 64 );
  ak_hash_file( &pctx->ctx, filename, hash, sizeof( hash ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return ak_false;
  }

 return ak_verifykey_verify_hash_schnorr( pctx, hash, pctx->ctx.data.sctx.hsize, sign);
}

bool_t ak_libakrypt_test_sign_schnorr( void )
{

    struct random generator;
    
    if(ak_random_create_lcg( &generator ) != ak_error_ok ) {
     ak_error_message( ak_error_ok, __func__, "incorrect creation of random generator" );
     return ak_false;
   }
	
 /* секретные ключи определяются последовательностями байт */
 /* d = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"; */
  ak_uint8 key256[32] = {
   0x28, 0x3B, 0xEC, 0x91, 0x98, 0xCE, 0x19, 0x1D, 0xEE, 0x7E, 0x39, 0x49, 0x1F, 0x96, 0x60, 0x1B,
   0xC1, 0x72, 0x9A, 0xD3, 0x9D, 0x35, 0xED, 0x10, 0xBE, 0xB9, 0x9B, 0x78, 0xDE, 0x9A, 0x92, 0x7A };

 /* определяем значение открытого ключа
     Q.x = 7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b
     Q.y = 26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da
     Q.z = 0000000000000000000000000000000000000000000000000000000000000001 */
  ak_mpzn256 pkey256x =
    { 0x6689dbd8e56fd80b, 0x8585ba1d4e9b788f, 0xd8595bec458b50c5, 0x7f2b49e270db6d90 };
  ak_mpzn256 pkey256y =
    { 0xdffb101a87ff77da, 0xaf64d1c593d26627, 0x85c8413a977b3cbb, 0x26f1b489d6701dd1 };
  ak_mpzn256 pkey256z = { 0x01, 0x0, 0x0, 0x0 };

 /* е = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5 */
  ak_uint64 e256[ak_mpzn256_size]  =
    { 0x67ECE6672B043EE5LL, 0xCE52032AB1022E8ELL, 0x88C09C52E0EEC61FLL, 0x2DFBC1B372D89A11LL };

 /* k = 77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3 */
  ak_uint64 k256[ak_mpzn256_size]  =
    { 0x4FED924594DCEAB3LL, 0x6DE33814E95B7FE6LL, 0x2823C8CF6FCC7B95LL, 0x77105C9B20BCD312LL };

#ifndef AK_LITTLE_ENDIAN
  int i = 0;
#endif
  struct signkey sk;
  ak_uint8 sign[128];
  ak_uint8 hash_out[64];
  struct verifykey pk;
  int error = ak_error_ok, audit = ak_log_get_level();

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing digital signatures started" );

 /* 0. Тестируем алгоритм Шнорра на контантных значениях--------------------------- */

 if(( error = ak_signkey_create( &sk,
                         (ak_wcurve) &id_tc26_gost_3410_2012_256_paramSetTest )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,
                               "incorrect creation of 256 bits secret key for GOST R 34.10-2012" );
    return ak_false;
  }
  if(( error = ak_signkey_set_key( &sk, key256, sizeof( key256 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a constant key value" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }
  memset( sign, 0, 64 );



  ak_signkey_sign_const_values_schnorr( &sk, k256, (ak_uint64 *)e256, sign, hash_out);


  if(( error = ak_verifykey_create_from_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }
  ak_signkey_destroy( &sk );

  if( ak_mpzn_cmp( pk.qpoint.x, pkey256x, pk.wc->size )) {
     ak_ptr_is_equal_with_log( pk.qpoint.x, pkey256x, pk.wc->size*sizeof( ak_uint64 ));
     ak_error_message( ak_error_not_equal_data, __func__ , "public key x-coordinate is wrong" );
     ak_verifykey_destroy( &pk );
     return ak_false;
   }
  if( ak_mpzn_cmp( pk.qpoint.y, pkey256y, pk.wc->size )) {
     ak_ptr_is_equal_with_log( pk.qpoint.y, pkey256y, pk.wc->size*sizeof( ak_uint64 ));
     ak_error_message( ak_error_not_equal_data, __func__ , "public key y-coordinate is wrong" );
     ak_verifykey_destroy( &pk );
     return ak_false;
   }
  if( ak_mpzn_cmp( pk.qpoint.z, pkey256z, pk.wc->size )) {
     ak_error_message( ak_error_not_equal_data, __func__ , "public key y-coordinate is wrong" );
     ak_verifykey_destroy( &pk );
     return ak_false;
   }
#ifndef AK_LITTLE_ENDIAN
  for( i = 0; i < ak_mpzn256_size; i++ ) ((ak_uint64 *)e256)[i] = bswap_64( e256[i] );
#endif
  if( ak_verifykey_verify_hash_schnorr( &pk, e256, sizeof( e256 ), sign)) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_verifykey_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_destroy( &pk );

#ifndef AK_LITTLE_ENDIAN
  for( i = 0; i < ak_mpzn256_size; i++ ) ((ak_uint64 *)e256)[i] = bswap_64( e256[i] );
#endif


    /* 1. Тестируем алгоритм Шнорра на файле Makefile--------------------------- */

    if(( error = ak_signkey_create( &sk,
                         (ak_wcurve) &id_tc26_gost_3410_2012_256_paramSetTest )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,
                               "incorrect creation of 256 bits secret key for GOST R 34.10-2012" );
    return ak_false;
  }
  if(( error = ak_signkey_set_key( &sk, key256, sizeof( key256 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a constant key value" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }
  memset( sign, 0, 64 );

  /* вырабатываем случайное число */
  memset( k256, 0, sizeof( ak_uint64 )*ak_mpzn256_size );
  if(( error = ak_mpzn_set_random_modulo( k256, (( ak_wcurve )sk.key.data)->q,
                                (( ak_wcurve )sk.key.data)->size, &generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "invalid generation of random value");



  ak_signkey_sign_file_schnorr( &sk, k256, "Makefile", sign, hash_out);

  if(( error = ak_verifykey_create_from_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }
  ak_signkey_destroy( &sk );

  if( ak_mpzn_cmp( pk.qpoint.x, pkey256x, pk.wc->size )) {
     ak_ptr_is_equal_with_log( pk.qpoint.x, pkey256x, pk.wc->size*sizeof( ak_uint64 ));
     ak_error_message( ak_error_not_equal_data, __func__ , "public key x-coordinate is wrong" );
     ak_verifykey_destroy( &pk );
     return ak_false;
   }
  if( ak_mpzn_cmp( pk.qpoint.y, pkey256y, pk.wc->size )) {
     ak_ptr_is_equal_with_log( pk.qpoint.y, pkey256y, pk.wc->size*sizeof( ak_uint64 ));
     ak_error_message( ak_error_not_equal_data, __func__ , "public key y-coordinate is wrong" );
     ak_verifykey_destroy( &pk );
     return ak_false;
   }
  if( ak_mpzn_cmp( pk.qpoint.z, pkey256z, pk.wc->size )) {
     ak_error_message( ak_error_not_equal_data, __func__ , "public key y-coordinate is wrong" );
     ak_verifykey_destroy( &pk );
     return ak_false;
   }
#ifndef AK_LITTLE_ENDIAN
  for( i = 0; i < ak_mpzn256_size; i++ ) ((ak_uint64 *)e256)[i] = bswap_64( e256[i] );
#endif

  if( ak_verifykey_verify_file_schnorr( &pk, "Makefile", sign)) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_verifykey_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_destroy( &pk );

#ifndef AK_LITTLE_ENDIAN
  for( i = 0; i < ak_mpzn256_size; i++ ) ((ak_uint64 *)e256)[i] = bswap_64( e256[i] );
#endif

    return ak_true;
}
