> A wheelbarrow ran over the flag. Can you fix it?

Looking at the chal description, we can speculate that the flag has something to do with a wheel barrow

Google wheel barrow cipher, and go to the first link: https://www.dcode.fr/burrows-wheeler-transform

If we brute force decrypt, we get multiple results, but we know the flag starts with `uoftctf{` (8 characters) so lets use the one which is similar to the flag format:

`LWPMGMP{NRN_XWL_BDWO_MZA_PRIQM_QLKQMRMLMRWD_GRFZAI_NEMAQ_KEGB_MW_600_KG}`

We know the flag starts with `uoftctf` so we can map those letters to beginning of the flag:

`LWPMGMP`
 |||||||
 vvvvvvv
`uoftctf`

Notice how the letter `f` is mapped to `P` and `t` is mapped to `M`. This is a simple substitution cipher. We can use a substitution cipher solver to get the flag.

Go to https://quipquip.com and paste the ciphertext in the input box. Click on `Solve -> Statistics` and you will get the flag.

Flag: `UOFTCTF{DID_YOU_KNOW_THE_FIRST_SUBSTITUTION_CIPHER_DATES_BACK_TO_600_BC}`