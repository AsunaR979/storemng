import os

MAIL_PATH = '/etc/raid_emails'
MAIL_CONFIG_PATH = '/etc/raid_emails_config'


def getMails():

    file = open(MAIL_PATH, "r")
    lines = file.readlines()
    file.close()

    mailList = []

    for ele in lines:

        mailList.append(ele.split('\n')[0])

    return mailList

def getMailsConfig():

    file = open(MAIL_CONFIG_PATH, "r")
    lines = file.readlines()
    file.close()

    configLines = []

    for ele in lines:

        configLines.append(ele.split('\n')[0].split())

    configTableData = []

    for ele in configLines:

        if ele[1] == 'true':
            configTableData.append({'status': True, 'raidName': ele[0]})

        else:
            configTableData.append({'status': False, 'raidName': ele[0]})

    return configTableData

def main():

    mailList = getMails()

    mailConfigList = getMailsConfig()

    for ele in mailConfigList:

        if ele['status'] == True:

            for mail in mailList:
                
                cmd = 'mdadm --monitor ' + ele['raidName'] + ' --mail ' + mail + '&'
                os.system(cmd)



main()
