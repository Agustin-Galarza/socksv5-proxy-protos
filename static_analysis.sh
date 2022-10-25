analysis_folder=./static_analysis_results
valgrind_folder=$analysis_folder/valgrind
cppcheck_folder=$analysis_folder/cppcheck

valgrind_output_file=$valgrind_folder/out.txt
cppc_output_file=$cppcheck_folder/out.txt

default_target=./bin/socks_proxy

if [ $# -eq 0 ]
then
    target=$default_target
else
    target=${@}
fi

mkdir -p $valgrind_folder $cppcheck_folder

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --log-file=$valgrind_output_file \
         $target

# cppcheck -v --enable=all -I./src/includes ./src/main.c > $cppc_output_file