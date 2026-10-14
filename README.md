#CSE 425 Assignment 2

The following excerpt (log_provided.txt) was taken from the web server access log of a fictional course registration website on 10/8/2026. All hosts, IP addresses, and requests are synthetic. The internal campus network uses the 10.0.0.0/8 address range; all other addresses are external. Each line has the format: 
 
<line> <time> <source IP> "<method> <URI>" <HTTP status> "<User-Agent>" 

You can use AI (Gemini or others) to analyze the log and learn about the underlying attacks. Ask AI to write a program (Python is recommended) that reads the log and reports every line it considers a SQL injection (SQLi) attempt or part of a denial-of-service (DoS) attack, together with the reason for each alert. 

Your task is to determine whether the AI detector is correct, reproducible, and adequately justified. You are responsible for every claim in your submission. Credit is based on your analysis and evidence, not merely obtaining a list of alerts. 
 
Important: This is an offline exercise only. Run your program only on the log above and on log lines you write yourself. Do NOT send any crafted request to a real website or server, including MSU systems. 
 
1.	Evaluate the detection logic 
 
Label every line of the log yourself as SQLi, DoS, or benign, and give a one-sentence justification for each non-benign line. Is the AI’s detector signature-based, anomaly-based, or a combination of both (Lecture 8)? Explain what the HTTP status codes in the log (302, 500, 503, and 408) establish, and what they do not establish, about whether an attack succeeded. 
 
Select three lines you labeled as SQLi. For each, show the URL-decoded request and explain how it would change the server’s SQL query. For line L04, assume the server builds its query with the template in Problem 3, Question 5. Write out the resulting SQL string and determine whether it is syntactically valid. Does the 302 response prove that the login bypass succeeded? 
 
2.	Test the implementation 
 
Run the supplied program on the log. Submit your commands and relevant output. Compare the program’s alerts with your own labels and report the number of true positives, false positives, false negatives, and true negatives, as well as the precision and recall, for SQLi and DoS separately. 
 
Verify that: 
 
•	The program URL-decodes each request before matching, including input that has been encoded more than once. 
•	The program inspects every attacker-controlled field available in the log, not only the URI. 
•	Benign requests that contain a quote character or SQL keywords are not reported as attacks. 
•	The DoS logic does not depend on one exact URI being repeated. 
 
Then extend the log with at least two new SQLi lines that the program misses and two new benign lines that it wrongly flags. Rerun the program and show the output. Improve the program (with or without AI) and rerun it on the extended log. 

Finally, answer: If the detector raises no alert on tomorrow’s log, does that prove that the server was not attacked? Support your answer with reasoning or a counterexample from this log. 
 
 
3.	Individual explanation 
 
Be prepared for a brief individual discussion in which you explain a selected part of the code, interpret an experimental result, or evaluate a small modification to the problem without AI assistance. 
 
Submit: a small report including source code, README, the original and extended logs, and execution logs. Include a short AI-use statement describing which tools you used, what assistance they provided, and how you checked their output. 
