https://radzim.github.io/teaching/cybersecurity
#supervision #todo
## Supervision 2

1. Software Security
    - [2024 Paper 4 Question 8](https://www.cl.cam.ac.uk/teaching/exams/pastpapers/y2024p4q8.pdf)
    - SEED Lab: [Return to libc](https://seedsecuritylabs.org/Labs_20.04/Software/Return_to_Libc/) Tasks 1, 2, 3
    - SEED Lab: [Web_SQL_Injection](https://seedsecuritylabs.org/Labs_20.04/Web/Web_SQL_Injection/) Tasks 2, 3
2. Authentication
    - [2024 Paper 4 Question 7](https://www.cl.cam.ac.uk/teaching/exams/pastpapers/y2024p4q7.pdf)
3. Human Factors
    - If you wanted to steal my password, how would you go about it?
    - Check your guesses against this bcrypt hash: `$2b$12$gAMJML2.9ZtEuA7Q6zh04uQzt9dghaWpYRZa6VF4rsgVMmoYSlT8.`
    - Note: the above is a fake but realistic password. If you actually manage to find a real password of mine, I will be very impressed, but please do not go further than that and attempt to edit or read any of my data, lock me out, etc.


# Software Security 
![[Pasted image 20260515003658.png]]

a) 
In terms of cost. More runs are 50\$ per run, and longer inputs could cost you anywhere up to 327.68\$. So you would need to have at least 7 runs for the possibility of it being cheaper to run per input. And additionally on top of this, for longer inputs you still have the first run cost, and for each run you have to also add up the input costs as well which gets very large. As the first byte of the vulnerable buffer may appear anywhere within the byte region, if we assume it is random, then on average we would be paying 163.84\$ for the inputs if we did it multiple runs, but also with that 50\$ per run, that would get expensive. So ideally want to minimise the runs as much as possible

b)

Stack spraying region: overwrite return and nearby addresses so that one of the overwrites lands in the nop sled 
should come before (ie have lower addresses) 
buffer sites at the low addresses and the return addresses are higher 
stack spraying region overwrites saved return addresses with repeated copies of the guessed address pointing to nop sled 
if it was after then it would overwrite past the return addresses into the caller frames and would need to point somewhere beyond return address 

c)
Stack spraying region covers the uncertainty of where the buffer starts, and the nop sled only helps with precision once you know you are in the right area
Wider spray region means that any return address pointing into 0xffff600-0xffffe000 will hit a NOP
Input capped at 2048 bytes so you want to maximise coverage of the region 

^ not 100% sure about the distinctions between them 

d)
Goal : find the place to put the payload so that it runs and then setuid to boss.
Problem: We don't know where the vulnerable buffer appears in the region.

We have our large input area which covers all possible regions. 

Ideally each query should cut the remaining possibilities in half for where the vulnerable buffer lies . There are 327 places where the vulnerable buffer could be (100 bytes long). If you ran it 327 times that would be really expensive. 

The nop sled, shell code payload, and local variables are all on the stack. 

But if you go into the nop sled, doesn't it just keep executing all the way down into the shell code? So you'd only need one run? or am i misunderstanding

e)
length - total input size, prefilled with NOPs as much as possible 2048

payload Offset - not sure, somewhere towards the end (where in the input the shell code is placed), so depends on d 

ret Offset - 102 (buffer + 2 bytes for char locals)

ret Address - retAddress = 0xffff6000 + (16384 >> i) * (some adjustment based on previous result)

ret Copies - writes retire address starting at retoffset. should be big enough to guarantee that the saved return address gets overwritten . (2048 - retOffset) // 4 = 486 and fills the overflow region to make sure the return address gets hit


Not totally sure on this question. 

![[Pasted image 20260515003728.png]]
a) i) 
$N=l_a^{l_p}$ = total keyspace, number of possible passwords up to length $l_p$ over alphabet of size $l_A$ (or, distinct possible values the key can take)
$n_c$ = number of chains in the table 
$l_c$ = length of each chain 
$s$ = avaliable storage in bytes 
$l_d$ = bytes per stored endpoint 
$t_h$ = time per hash 

Under the no-collision condition, it takes up $n_c \times l_c$ distinct passwords 
for any alphanumeric password up to 15 characters , and then also the equality for the minimum length chain condition , attackers want to crack nay of the passwords. so assuming that each one is a distinct password, the number of passwords covered by the table is $n_c \times l_c$ 

$$n_c \times l_c >= N=l_a^{l_p}, n_c\times l_c = l^{l_p}$$
Becomes equality as want mininum
And also the table only stores the endpoints, which is $l_d$ bytes:
Total storage : 
$$n_c\times l_d <= s$$


then 
$$n_c = \frac{s}{l_d}$$
so
$$n_c = \frac {8 \times 10^{12}}{16} = 5\times 10^{11}chains $$


$l_c =\frac{l_a^{l_p}}{n_c}=\frac{l_a^{l_p}\times l_d}{s}$ . $l_a^{l_p} = 36^{15} = 22.1 \times 10^{23}$

$$l_c=\frac{2.2\times 10^{23}}{5 \times 10^{11}}=4.4\times10^{11}$$

passwords per chain 

ii)
table only stores chain endpoints. chain bodies are not stored, so to find out which chain a target digest belongs to then regenerate chains on the fly and check whether the regenerated value matches any stored endpoint 

Hash function (H)- what the application uses to hash
Reduction function (R)- maps it back to the password. Not the inverse of hash but it produces some valid password ... ?
Chain construction - alternate between the hashing and the reduction 

only the final one is stored

Goal: given target d, find a password p such that H(p) = d
if d corresponds to a password at position i with some chain, applying R and H alternately will reproduce endpoint. Which i assume is the password we want? 

current = target 
for i from 0 to l_c:
	if current i appears as an endpoint, then we can then regenerate it from the start to recover p 
		for j from 0 to (l_c - 2 - i):
			p = R(H(p))
		candidate = p
		if H(candidate) = d:
			return candidate 
	current = H(R(current))

return not found 

iii)
need to compute every chain in full to find endpoint 
chain length l_c  linked by alternating H and R 
l_c hashes computed, one per password
n_h = no of hashes 
$n_h = n_c \times l_c$ hash computations required 
$n_h = l_a^{l_p}$
36^15 = 2.22 x 10^23 
one hash for every password the table covers 

iv) 
$$t_s = n_h \times t_h = 2.2 \times 10^{23} \times 10^{-5}s=2.2\times10^{18}s$$
which is like 7 x 10^10 years
a long time.....

CPU -> GPU
Parralel hash threads. 

(i had to google this, not sure how i would get the numbers in an exam)
For a hash like SHA-256, high end GPU at 10^10 hashes per sec vs CPU at 10^7
each chain is independent for hashing 
so you can use all of the parralel threads of a GPU to get 1000x a CPU core performance

Bank of GPUs
a much bigger scale, say like 100

Distributed pool of collaborators : botnet ? 
1000000 ish 
Volunteer or hijacked machines can contribute. Some botnet reached around 10 million infected hosts. Imagine using the GPUs on those personal machines, 10 million potential GPUs.... 

if we combined all three, 
then 10^3 x 10^2 x 10^6 = 10^11
$t_parralel = \frac{t_s}{\sigma_total} = \frac{2.2\times 10^{18}}{10^{11}}= 2.2 \times 10^7$
which in seconds, is about 8 months 
$$

$$
b) 
Hash collision, two distinct inputs produce same output under a hash function 
x != y, but H(x) = H(y)
H maps infitie input space to finite output space 
by pigeonhole principle then there are infinitely many inputs that must collide into each output 
the teenagers assume that every position in every chain covers a distinct password 

From the notes / Hellman 
probability that given a password it is covered by a table of $n_c$ keychains if length l_c over keyspace N is  

$$P {covered} \approx 1-e^{-n_cl_c/N}$$
Full coverage mean = N so it is e ^ -1
which is roughly 0.63
so covers 63% of the keyspace 





---

Human Factors
    - If you wanted to steal my password, how would you go about it?
    - Check your guesses against this bcrypt hash: `$2b$12$gAMJML2.9ZtEuA7Q6zh04uQzt9dghaWpYRZa6VF4rsgVMmoYSlT8.`
    - Note: the above is a fake but realistic password. If you actually manage to find a real password of mine, I will be very impressed, but please do not go further than that and attempt to edit or read any of my data, lock me out, etc.


**How I would go about it:**
If some site you signed up for a while ago got breached and you did not change your password, then the login is likely still out there somewhere. So I could buy some blackmarket data / see if it is online and check for the password there. 
Phising. Could send an email from a genuine sounding person or (as per last week, spoof from a trusted person (but also the spoofing can be traced on the server)), with a trusted sounding email, get them to click the link on it, and then from there then have a fake login page, in which the password needs to be entered and can be collected. Doesn't really work if there is a password autofill thing, as then the passoword won't autofill. I usually use randomly generated passwords so I wouldn't be able to autofill into a fake site. 
If you can convince your mobile character to port your number to their SIM, then the account could be reset with SMS codes from 2FA. 
If you're in a cafe and you type in your password somewhere, if it was clear enough then I could probably see you typing in your password. Or even if you left it unlocked and went to get a coffee then i could have automatic access by taking the unlocked device . 
Man in the middle attack (but i'm assuming passwords would be sent encrypted)

b)
I tried hashcat with lots of common passwords. Although it overloaded by GPU and it crashed my computer....
tried again with a lower workload  (-w1) not (-w3)
![[Pasted image 20260517114131.png]]

Also am trying a bad phishing attach which you will probably recognise, but here is the password you may have inputted: {{PASSWORD}}
Is not saved anywhere 



# Seed Labs 

am doing today so will update as I do them . But I am not planning to take cybersecuirty questions on the exam so will probably focus my time on other revision if I am being honest. Will try to do the buffer overflow one as i think that one is important. 

*Buffer overflow* 


*Return to libc*


*Web SQL Injection* 