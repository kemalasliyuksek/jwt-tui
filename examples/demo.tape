# vhs tape — render with `vhs examples/demo.tape` to produce assets/demo.gif.
# https://github.com/charmbracelet/vhs

Output assets/demo.gif

Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"

Type "jwt-tui decode 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'"
Enter
Sleep 2s

Type "jwt-tui sign --alg HS256 --secret 'shh' --payload '{\"sub\":\"alice\",\"iat\":1700000000}'"
Enter
Sleep 2s

Type "jwt-tui --lab attack alg-none 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AA'"
Enter
Sleep 2s

Type "jwt-tui"
Enter
Sleep 5s
Type "?"
Sleep 3s
Type "q"
