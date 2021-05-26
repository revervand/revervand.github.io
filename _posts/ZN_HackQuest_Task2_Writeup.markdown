---
layout: post
title:  "ZeroNights 2021 HackQuest -- Task 2 -- NOT A PROBLEM"
date:   2021-05-26 21:56:00 +0300
categories: reverse zeronights hackquest ransomware windows
---

**ZeroNights 2021 HackQuest -- Task 2 -- NOT A PROBLEM.**

*Type: CTF task*

*Platform: Windows x86*

*Category: Reverse*

*Idea: ransomware encrypted one file, need to decrypt file*

It was a simple reverse-engineering task. But there was a mistake in the
first version of this task. I will analyze both versions of this task.

Let's look at description.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image1.png){width="6.489583333333333in"
height="3.5833333333333335in"}

So, we have something of ransomware on Windows and encrypted file.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image2.png){width="3.8854166666666665in"
height="0.75in"}

If we load this binary in IDA, then we will see that it not packed. This
already makes the task easier. In the beginning, we may notice some
useless checks (language and time) that prevent it from starting on the
machine. We can just remove them.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image3.png){width="4.229166666666667in"
height="3.031363735783027in"}

There is also a whole function with testing various analysis and
debugging tools. But we can also patch it so that it always returns 0.
Part of this function in the image below.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image4.png){width="6.496527777777778in"
height="3.1131944444444444in"}

Patch is simple.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image5.png){width="3.4166666666666665in"
height="1.125in"}

Now we need to find encryption function. I just trying to find some
crypto constants, and found AES sbox in memory.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image6.png){width="6.496527777777778in"
height="1.0645833333333334in"}

Now you can find where the encryption takes place by cross-referencing
(xrefs).

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image7.png){width="6.489583333333333in"
height="1.6145833333333333in"}

Using the links, we find such a code (picture above) and it is very
similar to the AES-CFB mode. Now we need to figure out how the key and
the initialization vector are formed.

The function in which the encryption function is called initially checks
if we have found the right folder. If so, then we calculate some
checksum from the name of the file in the folder, after which this value
is used as an initializer of some random generator.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image8.png){width="6.496527777777778in"
height="4.374305555555556in"}

Next, using this generator, we get the values of the key and the
initialization vector.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image9.png){width="6.496527777777778in"
height="2.6506944444444445in"}

And it was in this place that a mistake was made. The fact is that AES
256 was chosen and the key size was 32 bytes, and the size of the
initialization vector was 16 bytes. But if you look closely at how much
memory is allocated for the key and the vector (56-59 lines), then you
can understand that there are only 8 bytes, which means that the
remaining bytes will be taken from the heap, where any bytes can be
located. As a result, the file cannot be decrypted.

This bug was fixed in the second version (After 17 hours from the start
of the task).

Fix in the image below.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image10.png){width="6.496527777777778in"
height="2.9125in"}

And now we have 32 bytes for key and 32 bytes for iv (Although in fact
the second 16 bytes are not processed). After the fix, all the solutions
to the task came down to set a breakpoint in one place and dumping the
key and the IV.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image11.png){width="6.496527777777778in"
height="2.0875in"}

And just dump key and IV from heap.

Key: 2D91949EA0C067B0BCF4F47F066D2B39B0A54F78FBF5DB2BA021A1F10DE50FC2

IV: 7925CFE7133F19A8C6A14D3868B8E1BC

Now you just need to decrypt the file. Although I had some problems with
the CFB mode (it only decoded the first 16 bytes correctly), I used the
OPENPGP mode, which was almost the same and got everything except the
first two blocks, but that was enough to unpack the file and get the
flag.

Code to decrypt:

{% highlight python %}
from Crypto.Cipher import AES
from binascii import unhexlify

key =
unhexlify(\"2D91949EA0C067B0BCF4F47F066D2B39B0A54F78FBF5DB2BA021A1F10DE50FC2\")
iv = unhexlify(\"7925CFE7133F19A8C6A14D3868B8E1BC\")
data = open(\"plan_important.docx\",\'rb\').read()

ctx = AES.new(key, AES.MODE_OPENPGP, iv=iv)
out = ctx.decrypt(data)

fd = open(\"out.docx\", \'wb\')
fd.write(out)
fd.close()
{% endhighlight %}

After decryption I got this file.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image12.png){width="6.40625in" height="2.75in"}

And I unpacked it with a zip. In word/document.xml I found the flag.

![](/assets/2021-05-26-ZeroNights-HackQuest-Day-2-Not-a-problem/image13.png){width="6.496527777777778in"
height="1.3743055555555554in"}

Flag: ZN\_ HOHrTOPUu6fmFTdWJ67W\_ nUwHpcPS12b9gqp9W6oa

**Summary**: It seemed to me that the task was too easy for such a cool
hack quest. Also, the mistakes made by the developer look very childish
and it is not clear why it was written that the error was in the
library. Obviously, the error was in the custom code and not in the AES
implementation.
