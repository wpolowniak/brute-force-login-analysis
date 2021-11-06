# Identify Brute-Force Login Attack
I'd like to demonstrate my analytical skills and thought process by working through an analysis of a website's authentication log to identify whether the website was subject to a brute-force login attack.

I searched the web for a dataset to analyze and came across a .txt file containing authentication log records for a small website, which someone posted online with the question, "Am I experiencing a brute force attack?" (source: https://security.stackexchange.com/questions/110706/am-i-experiencing-a-brute-force-attack)

I then did some data exploration and visualization on the data to identify whether and when an attack was happening, and which IP addresses seemed problematic.

The full analysis can be found in the Jupyter notebook called `brute-force-login.ipynb`, in the `notebooks` folder.

**Disclaimer:** The following is only one "quick and dirty" way to approach this problem. The level of sophistication can be tailored to the scope of the analysis and to the type of data that is available for querying.