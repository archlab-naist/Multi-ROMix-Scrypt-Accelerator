# include = 
# g++ -I$ARGUMENTS['incl'] -v $ARGUMENTS['src'] -o $ARGUMENTS['des']
# ./


for ARGUMENT in "$@"
do

    KEY=$(echo $ARGUMENT | cut -f1 -d=)
    VALUE=$(echo $ARGUMENT | cut -f2 -d=)   

    case "$KEY" in
            incl)               INCLUDE=${VALUE} ;;
            src)                SOURCE=${VALUE} ;;  
            des)                DESTINATION=${VALUE};;   
            *)   
    esac    


done


g++ -lc++ -I$INCLUDE $SOURCE -o $DESTINATION
echo "Compiled file"
echo "INCLUDE = $INCLUDE"
echo "SOURCE = $SOURCE"
echo "DESTINATION = $DESTINATION"
echo "Execute $DESTINATION"
./$DESTINATION