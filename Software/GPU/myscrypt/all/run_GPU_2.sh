nvcc test_gpu_official_2.cu -o out
#!/bin/bash
#echo `date +%s.%N`
start_time=`date +%s`
#./out > test_content.txt
./out
#echo `date +%s.%N`
end_time=`date +%s`
echo execution time was `expr $end_time - $start_time` s.
