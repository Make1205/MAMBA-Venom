#!/usr/bin/env bash
# Central Frost profile metadata for benchmark/CSV harnesses.
# Sizes are CRYPTO_* byte sizes (KEM secret key size for sk_bytes), derived
# from the Frost paper parameters for 128/192/256 and the retained repository
# extension parameters for 384/512 using the unified size formulas.

frost_level_params(){
  case "$1" in
    128) echo "q=32768,qbits=15,n=512,m=512,ell=8,eta_s=2,eta_r=2,b_msg=2,t_pk=10,t_u=10,t_v=8" ;;
    192) echo "q=65536,qbits=16,n=920,m=920,ell=8,eta_s=1,eta_r=1,b_msg=3,t_pk=12,t_u=11,t_v=7" ;;
    256) echo "q=65536,qbits=16,n=1288,m=1288,ell=8,eta_s=1,eta_r=1,b_msg=4,t_pk=13,t_u=13,t_v=7" ;;
    384) echo "q=262144,qbits=18,n=2176,m=2176,ell=8,eta_s=3,eta_r=3,b_msg=6,t_pk=16,t_u=15,t_v=13" ;;
    512) echo "q=1048576,qbits=20,n=3072,m=3072,ell=8,eta_s=4,eta_r=4,b_msg=8,t_pk=18,t_u=18,t_v=11" ;;
    *) echo "unknown Frost level: $1" >&2; return 1 ;;
  esac
}

frost_expected_sizes(){
  case "$1" in
    128) echo "5152,5216,6752,16" ;;
    192) echo "11072,10208,12976,24" ;;
    256) echo "16776,16832,19416,32" ;;
    384) echo "34848,32776,41440,48" ;;
    512) echo "55328,55416,67680,64" ;;
    *) echo "unknown Frost level: $1" >&2; return 1 ;;
  esac
}
