 #include <libakrypt-internal.h>

 void ak_signkey_sign_const_values_schnorr( ak_signkey sctx, ak_uint64 *k, ak_uint64 *e, ak_pointer out, ak_uint8* hash_out)
{

//   ak_uint32 steps;
  struct hash ctx; /* контекст функции хеширования */
//   struct random rnd;
  int error = ak_error_ok;
//   size_t len, offset;
  int audit = ak_log_get_level();

 /* буффер длиной 32 байта (256 бит) для хранения результата */
//   ak_uint8 buffer[512], *ptr = buffer;



  ak_mpzn512 r, s;
  ak_mpzn512 x, y, z;
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;

 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );

  

  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

//   printf("\n r:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.x[i]);
//     printf("%lld ", r[i]);
//   }

  ak_mpzn_rem(x, wr.x, wc->q, wc->size );
  ak_mpzn_rem(y, wr.y, wc->q, wc->size );
  ak_mpzn_rem(z, wr.z, wc->q, wc->size );

//   printf("\n cpoint.x:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.x[i]);
//     printf("%lld ", x[i]);
//   }
//   printf("\n cpoint.y:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.y[i]);
//     printf("%lld ", y[i]);
//   }

//   printf("\n cpoint.z:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.z[i]);
//     printf("%lld ", z[i]);
//   }

//   printf("\n ppoint.x:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.x[i]);
//     printf("%lld ", &wc->point.x[i]);
//   }
//   printf("\n ppoint.y:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.y[i]);
//     printf("%lld ", &wc->point.y[i]);
//   }

//   printf("\n ppoint.z:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.z[i]);
//     printf("%lld ", &wc->point.z[i]);
//   }

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
  // ak_mpzn_mul_montgomery( wr.y, wr.y, 1, wc->q, wc->nq, wc->size ); /* wr.y <- k*e */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

  // посчитать хэш от s||C:
  fflush(stdout);
  ak_uint64 *concatenate_s_c = malloc((ak_mpzn256_size*3 + ak_mpzn256_size) * sizeof(ak_uint64));
  // if(result == (ak_uint64*)NULL) {
      // exit(-1);
  // }

  // printf("\n сpoint.x:\n");
  // for (size_t i = 0; i < 8; i++){
  //   // printf("%d ", cpoint.x[i]);
  //   printf("%lld ", wr.x[i]);
  // }
  // printf("\n сpoint.y:\n");
  // for (size_t i = 0; i < 8; i++){
  //   // printf("%d ", cpoint.y[i]);
  //   printf("%lld ", wr.y[i]);
  // }

  // printf("\n сpoint.z:\n");
  // for (size_t i = 0; i < 8; i++){
  //   // printf("%d ", cpoint.z[i]);
  //   printf("%lld ", wr.z[i]);
  // }


  fflush(stdout);
  memcpy(concatenate_s_c, e, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %d, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size), wr.x[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size) / 8, x, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %d, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size + ak_mpzn512_size), wr.y[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*2) / 8, y, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %d, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size + ak_mpzn512_size * 2), wr.z[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*3) / 8, z, ak_mpzn256_size * sizeof(ak_uint64));
	fflush(stdout);
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
    exit(-1);
  }

//   printf("\n concatenate_s_c\n");
// 	  for (size_t i = 0; i < 16; i++){
// 	    printf("%lld ", concatenate_s_c[i]);
// 	  }

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

  // printf("\n HASH FROM SIGNATURE0:\n");
	//   for (size_t i = 0; i < 32; i++){
	//     printf("%x ", hash_out[i]);
	//   }

  // if(( result = ak_ptr_is_equal_with_log( hash_out, concatenate_s_c, 32 )) != ak_true ) {
    // ak_error_message( ak_error_not_equal_data, __func__ ,
                                             // "hash streebog is wrong" );
    // exit(-1);
  // }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "hash streebog is Ok" );

 /* приводим s к обычной форме */
  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
 /* экспортируем результат  + добавить экспорт хэша ебаного */
  ak_mpzn_to_little_endian( s, wc->size, out, sizeof(ak_uint64)*wc->size, ak_true );
  ak_mpzn_to_little_endian( r, wc->size, (ak_uint64 *)out + wc->size, sizeof(ak_uint64)*wc->size, ak_true );
 /* завершаемся */

// printf("\n s in sign: \n");
//   for (size_t i = 0; i < 4; i++){
//     printf("%lld ", s[i]);
//   }
  
//   printf("\n r in sign: \n");
//   for (size_t i = 0; i < 4; i++){
//     printf("%lld ", r[i]);
//   }

  // ak_wpoint_pow( &cpoint, wc->point, s, wc->size, wc);

  

  memset( &wr, 0, sizeof( struct wpoint ));
  sctx->key.set_mask( &sctx->key );
  memset( r, 0, sizeof( ak_mpzn512 ));
  memset( s, 0, sizeof( ak_mpzn512 ));

}


int ak_signkey_sign_schnorr( ak_signkey sctx, ak_uint64 *k, ak_uint64 *e, ak_pointer out, ak_uint8* hash_out)
{

//   ak_uint32 steps;
  struct hash ctx; /* контекст функции хеширования */
//   struct random rnd;
  int error = ak_error_ok;
//   size_t len, offset;
  int audit = ak_log_get_level();
//   ak_mpzn512 k;

 /* буффер длиной 32 байта (256 бит) для хранения результата */
//   ak_uint8 buffer[512], *ptr = buffer;



  ak_mpzn512 r, s;
  ak_mpzn512 x, y, z;
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;


//   memset( k, 0, sizeof( ak_uint64 )*ak_mpzn512_size );
//   if(( error = ak_mpzn_set_random_modulo( k, (( ak_wcurve )sctx->key.data)->q,
//                                 (( ak_wcurve )sctx->key.data)->size, generator )) != ak_error_ok )
    // return ak_error_message( error, __func__ , "invalid generation of random value");

 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );

  

  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

//   printf("\n r:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.x[i]);
//     printf("%lld ", r[i]);
//   }

  ak_mpzn_rem(x, wr.x, wc->q, wc->size );
  ak_mpzn_rem(y, wr.y, wc->q, wc->size );
  ak_mpzn_rem(z, wr.z, wc->q, wc->size );

//   printf("\n cpoint.x:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.x[i]);
//     printf("%lld ", x[i]);
//   }
//   printf("\n cpoint.y:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.y[i]);
//     printf("%lld ", y[i]);
//   }

//   printf("\n cpoint.z:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.z[i]);
//     printf("%lld ", z[i]);
//   }

//   printf("\n ppoint.x:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.x[i]);
//     printf("%lld ", &wc->point.x[i]);
//   }
//   printf("\n ppoint.y:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.y[i]);
//     printf("%lld ", &wc->point.y[i]);
//   }

//   printf("\n ppoint.z:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.z[i]);
//     printf("%lld ", &wc->point.z[i]);
//   }

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
  // ak_mpzn_mul_montgomery( wr.y, wr.y, 1, wc->q, wc->nq, wc->size ); /* wr.y <- k*e */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

  // посчитать хэш от s||C:
  fflush(stdout);
  ak_uint64 *concatenate_s_c = malloc((ak_mpzn256_size*3 + ak_mpzn256_size) * sizeof(ak_uint64));
  // if(result == (ak_uint64*)NULL) {
      // exit(-1);
  // }

  // printf("\n сpoint.x:\n");
  // for (size_t i = 0; i < 8; i++){
  //   // printf("%d ", cpoint.x[i]);
  //   printf("%lld ", wr.x[i]);
  // }
  // printf("\n сpoint.y:\n");
  // for (size_t i = 0; i < 8; i++){
  //   // printf("%d ", cpoint.y[i]);
  //   printf("%lld ", wr.y[i]);
  // }

  // printf("\n сpoint.z:\n");
  // for (size_t i = 0; i < 8; i++){
  //   // printf("%d ", cpoint.z[i]);
  //   printf("%lld ", wr.z[i]);
  // }


  fflush(stdout);
  memcpy(concatenate_s_c, e, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %d, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size), wr.x[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size) / 8, x, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %d, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size + ak_mpzn512_size), wr.y[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*2) / 8, y, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %d, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size + ak_mpzn512_size * 2), wr.z[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*3) / 8, z, ak_mpzn256_size * sizeof(ak_uint64));
	fflush(stdout);
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
    exit(-1);
  }

//   printf("\n concatenate_s_c\n");
// 	  for (size_t i = 0; i < 16; i++){
// 	    printf("%lld ", concatenate_s_c[i]);
// 	  }

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

  // printf("\n HASH FROM SIGNATURE0:\n");
	//   for (size_t i = 0; i < 32; i++){
	//     printf("%x ", hash_out[i]);
	//   }

  // if(( result = ak_ptr_is_equal_with_log( hash_out, concatenate_s_c, 32 )) != ak_true ) {
    // ak_error_message( ak_error_not_equal_data, __func__ ,
                                             // "hash streebog is wrong" );
    // exit(-1);
  // }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "hash streebog is Ok" );

 /* приводим s к обычной форме */
  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
 /* экспортируем результат  + добавить экспорт хэша ебаного */
  ak_mpzn_to_little_endian( s, wc->size, out, sizeof(ak_uint64)*wc->size, ak_true );
  ak_mpzn_to_little_endian( r, wc->size, (ak_uint64 *)out + wc->size, sizeof(ak_uint64)*wc->size, ak_true );
 /* завершаемся */

// printf("\n s in sign: \n");
//   for (size_t i = 0; i < 4; i++){
//     printf("%lld ", s[i]);
//   }
  
//   printf("\n r in sign: \n");
//   for (size_t i = 0; i < 4; i++){
//     printf("%lld ", r[i]);
//   }

  // ak_wpoint_pow( &cpoint, wc->point, s, wc->size, wc);

  

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

// printf("\n sign in verify: \n");
//   for (size_t i = 0; i < 128; i++){
//     printf("0x%x ", sign[i]);
//   }
// printf("\n sizeof sign: %s\n", sizeof(sign));

//   ak_uint32 steps;
  struct hash ctx; /* ╨║╨╛╨╜╤В╨╡╨║╤Б╤В ╤Д╤Г╨╜╨║╤Ж╨╕╨╕ ╤Е╨╡╤И╨╕╤А╨╛╨▓╨░╨╜╨╕╤П */
//   struct random rnd;
  int error = ak_error_ok;
//   bool_t result = ak_true;
//   size_t len, offset;
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
  // printf("\n s in verify: \n");
  // for (size_t i = 0; i < 8; i++){
  //   printf("0x%d - %d ", s[i], sizeof(s[i]));
  // }
  
  // printf("\n r in verify: \n");
  // for (size_t i = 0; i < 8; i++){
  //   printf("0x%d - %d ", r[i], sizeof(r[i]));
  // }

  // printf("\n pctx->wc->size = %d\n", pctx->wc->size);
 /* импортируем подпись */
  ak_mpzn_set_little_endian( s, pctx->wc->size, sign, sizeof(ak_uint64)*pctx->wc->size, ak_true );
  ak_mpzn_set_little_endian( r, pctx->wc->size, ( ak_uint64* )sign + pctx->wc->size,
                                                      sizeof(ak_uint64)*pctx->wc->size, ak_true );

  // printf("\n s in verify: \n");
  // for (size_t i = 0; i < 4; i++){
  //   printf("%d ", s[i], sizeof(s[i]));
  // }
  
  // printf("\n r in verify: \n");
  // for (size_t i = 0; i < 4; i++){
  //   printf("%d ", r[i], sizeof(r[i]));
  // }

  memcpy( h, hash, sizeof( ak_uint64 )*pctx->wc->size );
#ifndef AK_LITTLE_ENDIAN
  for( i = 0; i < pctx->wc->size; i++ ) h[i] = bswap_64( h[i] );
#endif

  ak_mpzn_set( v, h, pctx->wc->size );
  ak_mpzn_rem( v, v, pctx->wc->q, pctx->wc->size );
  if( ak_mpzn_cmp_ui( v, pctx->wc->size, 0 )) ak_mpzn_set_ui( v, pctx->wc->size, 1 );
  ak_mpzn_mul_montgomery( v, v, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

  // /* вычисляем v (в представлении Монтгомери) */
  // ak_mpzn_set_ui( u, pctx->wc->size, 2 );
  // ak_mpzn_sub( u, pctx->wc->q, u, pctx->wc->size );
  // ak_mpzn_modpow_montgomery( v, v, u, pctx->wc->q, pctx->wc->nq, pctx->wc->size ); // v <- v^{q-2} (mod q)

  // /* вычисляем z1 */
  // ak_mpzn_mul_montgomery( z1, s, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  // ak_mpzn_mul_montgomery( z1, z1, v, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  // ak_mpzn_mul_montgomery( z1, z1, pctx->wc->point.z, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

  // /* вычисляем z2 */
  // ak_mpzn_mul_montgomery( z2, r, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  // ak_mpzn_sub( z2, pctx->wc->q, z2, pctx->wc->size );
  // ak_mpzn_mul_montgomery( z2, z2, v, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  // ak_mpzn_mul_montgomery( z2, z2, pctx->wc->point.z, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

 /* сложение точек и проверка */
  ak_wpoint_pow( &cpoint, &pctx->wc->point, s, pctx->wc->size, pctx->wc );
  ak_wpoint_pow( &tpoint, &pctx->qpoint, r, pctx->wc->size, pctx->wc );

//   printf("\n ppoint.x:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.x[i]);
//     printf("%lld ", &pctx->wc->point.x[i]);
//   }
//   printf("\n ppoint.y:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.y[i]);
//     printf("%lld ", &pctx->wc->point.y[i]);
//   }

//   printf("\n ppoint.z:\n");
//   for (size_t i = 0; i < 8; i++){
//     // printf("%d ", cpoint.z[i]);
//     printf("%lld ", &pctx->wc->point.z[i]);
//   }

  struct wpoint inverse_tpoint;
  ak_wpoint_set_wpoint( &inverse_tpoint, &tpoint,  pctx->wc );
  ak_mpzn_sub( inverse_tpoint.y,  pctx->wc->p, inverse_tpoint.y,  pctx->wc->size );
  ak_wpoint_add( &cpoint, &inverse_tpoint, pctx->wc );
  // ak_wpoint_sub(&cpoint, &tpointm pctx->wc);
  // tpoint.y = -tpoint.y;
  // ak_wpoint_add( &cpoint, &tpoint, pctx->wc );
  ak_wpoint_reduce( &cpoint, pctx->wc );
  // ak_mpzn_rem( cpoint.x, cpoint.x, pctx->wc->q, pctx->wc->size );

  ak_mpzn_rem(x, cpoint.x, pctx->wc->q, pctx->wc->size );
  ak_mpzn_rem(y, cpoint.y, pctx->wc->q, pctx->wc->size );
  ak_mpzn_rem(z, cpoint.z, pctx->wc->q, pctx->wc->size );
  
      // if(result == (ak_uint64*)NULL) {
          // exit(-1);
      // }

//       printf("\n cpoint.x:\n");
//   for (size_t i = 0; i < 8; i++){
//     printf("%lld ", x[i]);
//     // printf("%d ", &pctx->wc->point.x[i]);
//   }
//   printf("\n cpoint.y:\n");
//   for (size_t i = 0; i < 8; i++){
//     printf("%lld ", y[i]);
//     // printf("%d ", &pctx->wc->point.y[i]);
//   }

//   printf("\n cpoint.z:\n");
//   for (size_t i = 0; i < 8; i++){
//     printf("%lld ", z[i]);
//     // printf("%d ", &pctx->wc->point.z[i]);
//   }
  ak_uint64 *concatenate_s_c = malloc((ak_mpzn256_size*3 + ak_mpzn256_size) * sizeof(ak_uint64));

  memcpy(concatenate_s_c, hash, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %lld, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size), cpoint.x[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size) / 8, cpoint.x, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %lld, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size + ak_mpzn512_size), cpoint.y[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*2) / 8, cpoint.y, ak_mpzn256_size * sizeof(ak_uint64));
  // printf("\nCOPYING: %d, %lld, %d\n", concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size + ak_mpzn512_size * 2), cpoint.z[0], ak_mpzn512_size * sizeof(ak_uint64));
  memcpy(concatenate_s_c + sizeof(ak_uint64)*(ak_mpzn256_size*3) / 8, cpoint.z, ak_mpzn256_size * sizeof(ak_uint64));
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
      exit(-1);
    }
  // printf("\n sizeof=%d", sizeof())
//   printf("\n concatenate_s_c(from verify)\n");
// 	  for (size_t i = 0; i < 16; i++){
// 	    printf("%lld ", concatenate_s_c[i]);
// 	  }



  // Calculate the total size of the concatenated array
    // size_t totalSize = sizeof(hash) + sizeof(cpoint.x) + sizeof(cpoint.y) + sizeof(cpoint.z);
    // ak_uint64 result_c[28]; // Be sure that this array can hold all elements (4+8+8+8)

    // // Use pointer arithmetic and memcpy to copy each array into the result array
    // // ak_uint64* ptr = result_c;
    // ak_uint64* ptr = malloc((ak_mpzn512_size*3 + ak_mpzn256_size) * sizeof(ak_uint64));
    
    // // Copy arr1 into result
    // memcpy(ptr, hash, sizeof(hash));
    // ptr += 32 / 8;
    
    // // Copy arr2 into result
    // memcpy(ptr, cpoint.x, sizeof(cpoint.x));
    // ptr += 64 / 8;
    
    // // Copy arr3 into result
    // memcpy(ptr, cpoint.y, sizeof(cpoint.y));
    // ptr += 64 / 8;
    
    // // Copy arr4 into result
    // memcpy(ptr, cpoint.z, sizeof(cpoint.z));
    
    // Now result contains all the elements from arr1, arr2, arr3, and arr4.

    // Print the concatenated array to verify
    // for (size_t i = 0; i < 28; i++) {
    //     printf("%lld ", ptr[i]);
    // }
    // printf("\n");

    

    
    ak_hash_ptr( &ctx, concatenate_s_c, sizeof(concatenate_s_c) * 16, hash_out_new, sizeof( hash_out_new ) * 4);

    free(concatenate_s_c);

    if(( error = ak_error_get_value()) != ak_error_ok ) {
      ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
     return ak_false;
    //   exit(-1);
     }

  // //
    // if(( result = ak_ptr_is_equal_with_log( hash_out_new, concatenate_s_c, 32 )) != ak_true ) {
      // ak_error_message( ak_error_not_equal_data, __func__ , "hash streebog is wrong" );
       // exit(-1);
     // }

     if( audit >= ak_log_maximum )
     ak_error_message( ak_error_ok, __func__ , "hash streebog is Ok" );
	  
// 
	  // 
// 
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
//  bool_t ak_verifykey_verify_hash_schnorr( ak_verifykey pctx, const ak_pointer hash, const size_t hsize, ak_pointer sign, ak_uint8* hash_out)

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

 /* d = BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4 */
//   ak_uint8 key512[64] = {
//    0xd4, 0x8d, 0xa1, 0x1f, 0x82, 0x67, 0x29, 0xc6, 0xdf, 0xaa, 0x18, 0xfd, 0x7b, 0x6b, 0x63, 0xa2,
//    0x14, 0x27, 0x7e, 0x82, 0xd2, 0xda, 0x22, 0x33, 0x56, 0xa0, 0x00, 0x22, 0x3b, 0x12, 0xe8, 0x72,
//    0x20, 0x10, 0x8b, 0x50, 0x8e, 0x50, 0xe7, 0x0e, 0x70, 0x69, 0x46, 0x51, 0xe8, 0xa0, 0x91, 0x30,
//    0xc9, 0xd7, 0x56, 0x77, 0xd4, 0x36, 0x09, 0xa4, 0x1b, 0x24, 0xae, 0xad, 0x8a, 0x04, 0xa6, 0x0b };

 /* определяем значение открытого ключа
     Q.x = 115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1
     Q.y = 37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC
     Q.z = 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 */
//   ak_mpzn512 pkey512x =
//     { 0xDD33612CD530EFE1LL, 0xF75C45415C1D9DD9LL, 0x69BC5B924C8B4DDFLL, 0x5A515856D13314AFLL,
//       0x5B5C320C854621DDLL, 0xC4A85A65BE33C181LL, 0x48598D8AB9E740D4LL, 0x115DC5BC96760C7BLL };
//   ak_mpzn512 pkey512y =
//     { 0x7F35ECA93677BEECLL, 0x4C114E1F9339FDF2LL, 0xF0C70A2759A3CDB8LL, 0xEA199441D943FFE7LL,
//       0x639F5D7FB72AFD61LL, 0xE2634FA0503B3D52LL, 0x21DC3AC1B751CFA0LL, 0x37C7C90CD40B0F56LL };
//   ak_mpzn512 pkey512z = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

 /* е = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5 */
  ak_uint64 e256[ak_mpzn256_size]  =
    { 0x67ECE6672B043EE5LL, 0xCE52032AB1022E8ELL, 0x88C09C52E0EEC61FLL, 0x2DFBC1B372D89A11LL };
 /* е = 3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C */
//   ak_uint64 e512[ak_mpzn512_size]  =
//     { 0xC6777D2972075B8CLL, 0x407ADEDB1D560C4FLL, 0x4339976C647C5D5ALL, 0x7184EE536593F441LL,
//       0xA71D147035B0C591LL, 0x1B09B6F9C170C533LL, 0x5C4F4A7C4D8DAB53LL, 0x3754F3CFACC9E061LL };

 /* k = 77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3 */
  ak_uint64 k256[ak_mpzn256_size]  =
    { 0x4FED924594DCEAB3LL, 0x6DE33814E95B7FE6LL, 0x2823C8CF6FCC7B95LL, 0x77105C9B20BCD312LL };
 /* k = 359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1 */
//   ak_uint64 k512[ak_mpzn512_size]  =
//     { 0xA3AF71BB1AE679F1LL, 0x212273A6D14CF70ELL, 0x4434006011842286LL, 0x86748ED7A44B3E79LL,
//       0xD455986E364F3658LL, 0x946312120B39D019LL, 0xCC570456C6801496LL, 0x0359E7F4B1410FEALL };

 /* результирующие последовательности - электронные подписи, также представляются последовательностями байт */
//   ak_uint8 sign256[64] =
//     { 0x01, 0x45, 0x6c, 0x64, 0xba, 0x46, 0x42, 0xa1, 0x65, 0x3c, 0x23, 0x5a, 0x98, 0xa6, 0x02, 0x49,
//       0xbc, 0xd6, 0xd3, 0xf7, 0x46, 0xb6, 0x31, 0xdf, 0x92, 0x80, 0x14, 0xf6, 0xc5, 0xbf, 0x9c, 0x40,
//       0x41, 0xaa, 0x28, 0xd2, 0xf1, 0xab, 0x14, 0x82, 0x80, 0xcd, 0x9e, 0xd5, 0x6f, 0xed, 0xa4, 0x19,
//       0x74, 0x05, 0x35, 0x54, 0xa4, 0x27, 0x67, 0xb8, 0x3a, 0xd0, 0x43, 0xfd, 0x39, 0xdc, 0x04, 0x93 };

 /* r = 2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36
    s = 1081B394696FFE8E6585E7A9362D26B6325F56778AADBC081C0BFBE933D52FF5823CE288E8C4F362526080DF7F70CE406A6EEB1F56919CB92A9853BDE73E5B4A */
//   ak_uint8 sign512[128] =
//     { 0x10, 0x81, 0xB3, 0x94, 0x69, 0x6F, 0xFE, 0x8E, 0x65, 0x85, 0xE7, 0xA9, 0x36, 0x2D, 0x26, 0xB6,
//       0x32, 0x5F, 0x56, 0x77, 0x8A, 0xAD, 0xBC, 0x08, 0x1C, 0x0B, 0xFB, 0xE9, 0x33, 0xD5, 0x2F, 0xF5,
//       0x82, 0x3C, 0xE2, 0x88, 0xE8, 0xC4, 0xF3, 0x62, 0x52, 0x60, 0x80, 0xDF, 0x7F, 0x70, 0xCE, 0x40,
//       0x6A, 0x6E, 0xEB, 0x1F, 0x56, 0x91, 0x9C, 0xB9, 0x2A, 0x98, 0x53, 0xBD, 0xE7, 0x3E, 0x5B, 0x4A,
//       0x2F, 0x86, 0xFA, 0x60, 0xA0, 0x81, 0x09, 0x1A, 0x23, 0xDD, 0x79, 0x5E, 0x1E, 0x3C, 0x68, 0x9E,
//       0xE5, 0x12, 0xA3, 0xC8, 0x2E, 0xE0, 0xDC, 0xC2, 0x64, 0x3C, 0x78, 0xEE, 0xA8, 0xFC, 0xAC, 0xD3,
//       0x54, 0x92, 0x55, 0x84, 0x86, 0xB2, 0x0F, 0x1C, 0x9E, 0xC1, 0x97, 0xC9, 0x06, 0x99, 0x85, 0x02,
//       0x60, 0xC9, 0x3B, 0xCB, 0xCD, 0x9C, 0x5C, 0x33, 0x17, 0xE1, 0x93, 0x44, 0xE1, 0x73, 0xAE, 0x36 };
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

//   printf("\n sign: \n");
//   for (size_t i = 0; i < 128; i++){
//     printf("0x%x ", sign[i]);
//   }
  // ak_signkey_sign_const_values( &sk, k256, (ak_uint64 *)e256, sign );
  // if( ak_ptr_is_equal_with_log( sign, ( ak_pointer )sign256, 64 )) {
    // if( audit >= ak_log_maximum )
      // ak_error_message( ak_error_ok, __func__ ,
         // "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  // } else {
     // ak_error_message( ak_error_not_equal_data, __func__ ,
      // "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
     // ak_signkey_destroy( &sk );
     // return ak_false;
   // }

//   printf("\nHASH FROM SIGNATURE:\n");
// 	  for (size_t i = 0; i < 32; i++){
// 	    printf("0x%x ", hash_out[i]);
// 	  }
//     printf("\n\n");

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
// printf("\n sign: \n");
//   for (size_t i = 0; i < 128; i++){
//     printf("0x%x ", sign[i]);
//   }
  if( ak_verifykey_verify_hash_schnorr( &pk, e256, sizeof( e256 ), sign)) {
  // if( ak_verifykey_verify_hash( &pk, e256, sizeof( e256 ), sign, hash_out)) {
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

//   printf("\n sign: \n");
//   for (size_t i = 0; i < 128; i++){
//     printf("0x%x ", sign[i]);
//   }
  // ak_signkey_sign_const_values( &sk, k256, (ak_uint64 *)e256, sign );
  // if( ak_ptr_is_equal_with_log( sign, ( ak_pointer )sign256, 64 )) {
    // if( audit >= ak_log_maximum )
      // ak_error_message( ak_error_ok, __func__ ,
         // "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  // } else {
     // ak_error_message( ak_error_not_equal_data, __func__ ,
      // "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
     // ak_signkey_destroy( &sk );
     // return ak_false;
   // }

//   printf("\nHASH FROM SIGNATURE:\n");
// 	  for (size_t i = 0; i < 32; i++){
// 	    printf("0x%x ", hash_out[i]);
// 	  }
//     printf("\n\n");

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
// printf("\n sign: \n");
//   for (size_t i = 0; i < 128; i++){
//     printf("0x%x ", sign[i]);
//   }
  if( ak_verifykey_verify_file_schnorr( &pk, "Makefile", sign)) {
  // if( ak_verifykey_verify_hash( &pk, e256, sizeof( e256 ), sign, hash_out)) {
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