# BypassAMSI_CSharp

Blog link: none


- Bypassing AMSI via "patch memory".
- Tested on x64/x86.
- Steps
	1. Locate amsi.dll's address.
	2. finding the "DllCanUnloadNow" base on the address
	3. Using egg hunt to find the function we need to patch.
	4. Patch it with the byte[] "patch64/patch86". 

- **You may need modify the code, make sure the code could by the EDR/AVs**
- I only tested on windows defender,works fine.

## Usage
1. Launch through a white-list application
- Without bypassing AMSI
	![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/WithoutBypassAMSI.png)
- With Bypassing AMSI
	![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/WithBypassAMSI.png)

## TO-DO list
- There are indeed other methods to bypass, I may gonna update about that.
- Obfuscated the code.


## Reference link:
	None :)
	Just Google it, too many documents about bypassing AMSI :)