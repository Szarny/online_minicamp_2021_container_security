echo "=== RESULT ==="
opa test test.rego
ret=$?
echo "==============\n"

if [ $ret -ne 0 ]; then
  echo "提出されたポリシーに誤りがあります。"
else
  echo "mc2021{The_first_step_of_Policy_as_Code}"
fi
