start_time=`date +%s`
./SCRYPT.exe
end_time=`date +%s`
echo execution time was `expr $end_time - $start_time` s.
