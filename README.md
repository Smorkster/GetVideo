GetVideo

This script reads a file containing a list of addresses with videos that wants to be downloaded. It is mainly created for YouTube, but the application YouTube-dl can also handle other sites.

Before downloading, the script checks of there are (persumed) enough free space on the disc. It then continues with fetching information about the video then starts downloading.

If the video is located on YouTube the video will be marked as watched if the user have provided login credentials.

The videos will be named as such:

  YouTube: date_of_publication YouTube-username videoname

  Other sites: Domain-name videoname
