D2


index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="45.77.210.24"
| stats count

index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="45.77.210.24"
| stats count by status_code
| sort status_code
