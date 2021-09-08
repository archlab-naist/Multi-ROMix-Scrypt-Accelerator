g++ test_scrypt_multithreads.cpp -lpthread

echo `date +%s.%N`
start_time=`date +%s`
./a.out
echo `date +%s.%N`
end_time=`date +%s`
echo execution time was `expr $end_time - $start_time` s.
