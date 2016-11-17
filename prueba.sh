clear
echo "javac src/cryptography/* -d ./"
javac src/cryptography/* -d ./
if [ $# -eq 3 ]; then
    plaintextFile=$1
    extention=$2
    testfile="cryptography.${3}"
    for x in ECB CBC CTR
    do
        for y in AES128 AES192 AES256 DES168
        do
            echo java $testfile $y $x $plaintextFile.$extention
            java $testfile $y $x $plaintextFile.$extention
            echo "Terminado!"
            echo cmp "${plaintextFile}.${extention}" "${plaintextFile}_${x}_${y}_Decipher.${extention}"
            cmp "${plaintextFile}.${extention}" "${plaintextFile}_${x}_${y}_Decipher.${extention}"
        done
    done
else
    echo "Necesito tres argumentos"
fi
    
