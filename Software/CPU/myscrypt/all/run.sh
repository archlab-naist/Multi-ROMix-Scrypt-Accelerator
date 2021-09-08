g++ test_scrypt_multithreads.cpp -lpthread

start_time=`date +%s`
./a.out
end_time=`date +%s`
echo execution time was `expr $end_time - $start_time` s.
