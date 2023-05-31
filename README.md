This script reads a file containing a list of addresses with videos that wants to be downloaded. It uses Youtube-dl to handle the downloading. It is mainly created for YouTube and SVT Play, but the application YouTube-dl can handle other sites.

Before downloading, the script checks if there are (persumed) enough free space on the disc. Minimum free space is 1,5 GB. It then reads inputfile and starts a job for each listed link.

If the video is located on YouTube, the video will be marked as watched if script is set to extract cookies, from Firefox or Chrome.

The videos will be named as such:

  * YouTube: `<Date of publication> <YouTube-username> <Videoname>`
  * SVT Play: `<Date of publication> SVT Play <Videoname>`
  * Other sites: `<Domain-name> <Videoname>`
