    ███╗   ███╗██╗   ██╗████████╗██╗     ██╗    ██╗   ██╗███████╗███████╗██████╗     ███████╗██╗██╗     ███████╗    ███████╗██╗  ██╗ █████╗ ██████╗ ███████╗
    ████╗ ████║██║   ██║╚══██╔══╝██║     ██║    ██║   ██║██╔════╝██╔════╝██╔══██╗    ██╔════╝██║██║     ██╔════╝    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝
    ██╔████╔██║██║   ██║   ██║   ██║     ██║    ██║   ██║███████╗█████╗  ██████╔╝    █████╗  ██║██║     █████╗      ███████╗███████║███████║██████╔╝█████╗  
    ██║╚██╔╝██║██║   ██║   ██║   ██║     ██║    ██║   ██║╚════██║██╔══╝  ██╔══██╗    ██╔══╝  ██║██║     ██╔══╝      ╚════██║██╔══██║██╔══██║██╔══██╗██╔══╝  
    ██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗██║    ╚██████╔╝███████║███████╗██║  ██║    ██║     ██║███████╗███████╗    ███████║██║  ██║██║  ██║██║  ██║███████╗
    ╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝     ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                                                                                                        


# MUTLI_USER_FILE_SHARE

### this project implement a linux software to cipher files and share them with friends!


##### Features 
* Cipher / Uncipher 
* Sign / Verify 




##### Usage
You will need couple of public/private key to cipher and sign. 
```$ openssl genrsa 2048 > my_ciph_priv.pem [my_ciph_pub.pem]```
```$ openssl genrsa 2048 > my_sign_priv.pem [my_sign_pub.pem]```


Cipher mode
```$ multi_protect -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]```

Uncipher mode
```$ multi_protect -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>```




##### notes
This project is written in C language. It use MbedTls librairy. It use AES-CBC-256 (cipher), sha_256 (sign).








