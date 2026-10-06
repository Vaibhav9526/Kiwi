$ppt = New-Object -ComObject PowerPoint.Application
$pres = $ppt.Presentations.Open('D:\Hackathon\PROJECTS\Kiwi Mail\presentation\KIWI-SIH26159-SecureMailScope.pptx', $true, $false, $false)
New-Item -ItemType Directory -Force 'D:\Hackathon\PROJECTS\Kiwi Mail\presentation\sih-check' | Out-Null
$pres.SaveAs('D:\Hackathon\PROJECTS\Kiwi Mail\presentation\sih-check\slide', 18)
$pres.Close()
$ppt.Quit()
Write-Output "done"
