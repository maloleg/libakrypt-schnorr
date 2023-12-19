/* 0. Тестируем алгоритм Шнорра на контантных значениях (256 бит)--------------------------- */

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
