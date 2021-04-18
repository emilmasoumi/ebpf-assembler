#!/bin/bash

if [ -z $EBPF_AS ]; then
  echo "error: bash environment variable EBPF_AS is undefined."
  echo "The variable must be assigned the entire path to the assembler."
  echo "Example: \$ export EBPF_AS=\"home/username/ebpf-assembler/ebpf-as\""
  exit 1
fi

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

succeded=0
tests=0
echo "Running test files in $(dirname "$0")/input/true:"
for file in $(dirname "$0")/input/true/*.s
do
  ((tests++))
  $EBPF_AS "$file"
  if [ $? -eq 0 ]; then
    ((succeded++))
  else
    echo $''
    echo "$(basename -- $file) ${red}failed${reset} with output ^" $'\n'
    echo "printing $(basename -- $file):"
    cat $file
  fi
done
find $(dirname "$0")/input/true/. -type f ! -name "*.s" -exec rm {} \; &
echo $'\n--------------------------------'
echo "| $succeded/$tests tests in $(dirname "$0")/input/${green}true" \
     "${reset}succeded."
echo $'--------------------------------\n'

succeded=0
tests=0
echo "Running test files in $(dirname "$0")/input/false:"
for file in $(dirname "$0")/input/false/*.s
do
  ((tests++))
  $EBPF_AS "$file" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo $''
    echo "$(basename -- $file) ${red}failed${reset} with exit code 0" $'\n'
    echo "printing $(basename -- $file):"
    cat $file
  else
    ((succeded++))
  fi
done
find $(dirname "$0")/input/false/. -type f ! -name "*.s" -exec rm {} \; &
echo $'\n--------------------------------'
echo "| $succeded/$tests tests in $(dirname "$0")/input/${green}false" \
     "${reset}succeded."
echo $'--------------------------------\n'
