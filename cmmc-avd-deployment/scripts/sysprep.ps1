 #The script will disable BitLocker on all encrypted volumes and then wait for the decryption to complete. Once the decryption is complete, the script will run Sysprep to generalize the image and shut down the computer. 

if ((Get-BitLockerVolume).VolumeStatus -contains 'FullyEncrypted') {(Get-BitLockerVolume | Where-Object -Property VolumeStatus -eq 'FullyEncrypted').MountPoint | ForEach-Object -Process {Disable-BitLocker -MountPoint $_}}
do {
    $CurrentVolume = Get-BitLockerVolume| Where-Object -Property VolumeStatus -eq 'DecryptionInProgress'
    ('{0} {1}' -f $CurrentVolume.VolumeStatus, $CurrentVolume.EncryptionPercentage) 
    Start-Sleep 30 
} 
while ((Get-BitLockerVolume).VolumeStatus -contains 'DecryptionInProgress')

rmdir C:\Windows\Panther -Confirm:$false -Recurse
& "$env:SytemRoot\System32\Sysprep\sysprep.exe" /generalize /oobe /shutdown /quiet