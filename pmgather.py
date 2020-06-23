import click
import os
import psutil
import subprocess
import getpass
import datetime
from shutil import make_archive
from urllib.parse import unquote
from distutils.file_util import copy_file
from distutils.dir_util import copy_tree,mkpath
import distutils
import time
import mmap
import logging
import sys, traceback
import signal
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from multiprocessing import cpu_count

@click.command()

# Using options decorators for arguments
@click.option(
    '-l', '--path',
    prompt='Enter INFA_HOME',
    envvar='INFA_HOME',
    type=click.Path(
        exists=True
        ),
    help='INFA_HOME path'
    )

@click.option(
    '-p', '--proc',
    prompt='Provide the valid PID or the ServiceName',
    default=None,
    help='PID or the ServiceName'
    )

@click.option(
    '-d', '--delay',
    help='Delay interval (secs)',
    default=10,
    type=click.IntRange(
        min=1,
        max=3600,
        clamp=True
        ),
    show_default=True
    )

@click.option(
    '-i', '--itr',
    help='Number of iterations',
    default=1,
    type=click.IntRange(
        min=1,
        max=20,
        clamp=True
        ),
    show_default=True
    )

@click.option(
    '-r', '--rec',
    help='Either True or False. If True, application will gather PPID information recursively',
    default=False,
    type=bool,
    show_default=True
    )

@click.option(
    '-U', '--user',
    help='Either True or False. If True, application will bypass usr check',
    default=False,
    type=bool,
    show_default=True
    )

@click.option(
    '-s', '--strace',
    help='Strace runtime (secs)',
    default=60,
    type=click.IntRange(
        min=10,
        max=1200,
        clamp=True
        ),
    show_default=True
    )

def mainRun(path,proc,delay,itr,rec,user,strace):
    infa_home=path
    timeStamp=datetime.datetime.now().strftime("%d-%m_%H-%M%S")
    colPath='collect_pmgather/pmgather_{}'.format(timeStamp)
    try:
        os.makedirs(colPath)
    except PermissionError:
        print('No permissions to create directory at current working directory {}... exiting application ..'.format(colPath))
        logging.error("Failed to create directory {} due to permission issue".format(colPath))
        sys.exit()
    except OSError:
        print ('Creation of the directory {} failed ... exiting application'.format(colPath))
        logging.error("Failed to create directory {}".format(colPath))
        sys.exit()
    logger = logging.getLogger(__name__)
    log_format='%(asctime)s :: %(levelname)s :: %(threadName)s :: %(message)s'
    log_file_name=colPath+'/pmgather.log'
    logging.basicConfig(level=logging.DEBUG, format=log_format,filename=log_file_name,filemode='w')
    recRun=0
    runSys=False

    print('\n', "Validating provided details".center(100, '*'), '\n')

    # Checks INFA_HOME until it is valid
    while (checkInfaHome(infa_home)!=1):
        infa_home=input('Enter Correct path for INFA_HOME:\n')
        checkInfaHome(infa_home)
        print(infa_home)
    print('INFA_HOME correctly set :',infa_home)
    logging.info("INFA_HOME - {} validated successfully".format(path))

    # Displays the OS name
    try:
        print('OS Name is',os.uname()[0])
        logging.info("Operating System : {}".format(os.uname()[0]))
    except AttributeError:
        logging.error("Unsupported Operating System : Windows")
        print('OS Name is Windows')

    # Determine if the value passed in proc variable is a PID or a ServiceName
    if proc.isnumeric():
        detail=getPID(proc,user)
        #returns [pid,pName,usr,cmdLine,status]
    else:
        detail=getProcess(proc,user)
        #returns [pid,pName,usr,cmdLine,status]

    # Get jdk_home path
    jdkHome=getJDKhome(infa_home)
    logging.info("JDK used is : {}".format(jdkHome))
    logging.info("USERNAME : {}".format(getpass.getuser()))
    logging.info("HostName : {}".format(os.uname()[1]))
    logging.info("Arguments passed to command : {}\n".format(str(sys.argv)))
    logging.info("Total iterations per process : {itr}\n".format(itr=itr))
    logging.info("Deley between iterations : {dl}\n".format(dl=delay))
    logging.info("Strace runtime in secs : {strace}\n".format(strace=strace))

    # Invoke gather
    if rec:
        pidDict=getRecursive(detail[0],infa_home)
        maxRun=0
        pidPool=[]
        pNamePool=[]
        userPool=[]
        runSysPool=[]
        for p in pidDict:
            if pidDict[p][1]:
                maxRun+=1
        for i in pidDict:
            exec=pidDict[i]
            if exec[1]:
                recRun+=1
                runSys=recRun==maxRun
                detail=getPID(str(exec[0]),user)
                pName=i if detail[1]=='java' and i in ['AdminConsole','nodeJava'] else detail[1]
                pidPool.append(detail[0])
                pNamePool.append(pName)
                userPool.append(detail[2])
                runSysPool.append(runSys)
        #Run Gather concurrently for all with different threads from the thread pool
        with ThreadPoolExecutor(max_workers=cpu_count() - 1,thread_name_prefix = 'PMGather') as executor:
            try:
                results = executor.map(gather, repeat(infa_home),pidPool,pNamePool,userPool,repeat(itr),repeat(delay),repeat(jdkHome),repeat(colPath),repeat(rec),runSysPool,repeat(strace))
            except TypeError as e:
                logging.error("Unexpected Error while invoking gather for recursive contact Informatica Global Support")
                pass
        #Zip the artifacts after gather runs
        archive(colPath)
    else:
        try:
            gather(infa_home, detail[0], detail[1],detail[2],itr,delay,jdkHome,colPath,rec,runSys,strace)
            #gather(infa_home,pid,pName,user,itr,dl,jdkHome,colPath,rec,runSys)
            #Zip the artifacts after gather runs
            archive(colPath)
        except TypeError as e:
            logging.error("Unexpected Error while invoking gather contact Informatica Global Support")
            pass

def archive(path):
    try:
        print("Zipping the directory {}".format(path))
        make_archive(path,'zip',path)
        logging.info("Zipped the directory {}".format(path))
    except FileNotFoundError as e:
        logging.error("File \'{}\' not available for archive".format(path))
        pass

def checkInfaHome(path):
    '''Check if the INFA_HOME path is correct by validating with the directory structure'''
    isValid1=os.path.exists(os.path.join(path,"isp","config"))
    isValid2=os.path.exists(os.path.join(path,"tools","debugtools"))
    if isValid1 and isValid2:
        return 1
    else:
        return -1

def getJDKhome(path):
    '''Returns JDK Home of INFA'''
    if os.path.exists(os.path.join(path,"java","bin")):
        return path+'/java/bin'
    else:
        return path+'/tools/debugtools/java/bin'

def convBase64(proc_name,enc):
    '''Returns Base64 encoded string'''
    if enc:
        cmd='printf ' + proc_name + '| base64'
    else:
        cmd='printf ' + proc_name + '| base64 -d'
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output , error =process.communicate()
    return output.decode('utf-8').split("\n")[0]

def getProcess(proc,user):
    '''Returns process related information after
        validating the service name passed by user'''
    proc_name=proc.strip()
    nJava=convBase64(proc_name,True)
    runProc=None
    usr=None
    cmdLine=None
    pid=None
    pName=None
    status=None
    for p in psutil.process_iter(attrs=['pid','cmdline','name','username','status']):
        try:
            if len(p.info['cmdline'])>0 and (proc_name in str(p.info['cmdline']) or nJava in str(p.info['cmdline'])) and (not 'python' in p.info['cmdline']):
                cmdLine=p.info['cmdline']
                pName=p.info['name']
                pid=p.info['pid']
                usr=p.info['username']
                status=p.info['status']
                if pName == 'java':
                    for list_ in cmdLine:
                        if "-Dcatalina.base" in list_:
                            i=list_.split("/")[-1]
                            runProc='AdminConsole' if i == '_AdminConsole'else i
                        elif "-DFrameworksLogFilePath" in list_:
                            i=(list_.split("/")[-1]).split("_jsf.log")[0]
                            runProc='AdminConsole' if i == '_AdminConsole'else i
                        else:
                            pass
                    break
                elif not pName == 'java' and (nJava==cmdLine[2] or nJava==cmdLine[3]):
                    runProc=proc_name
                    break
                else:
                    pass
            else:
                pass
        except (TypeError, IndexError) as e:
            logging.error("Unexpected error occured while fetching the process information contact Informatica Global Support")
            pass
    # Validates if the process is defunct
    if status == 'zombie':
        print('Zombie Process detected : Parent process is dead. Kill and restart required, exiting application ...')
        logging.error("PID : {pid} detected as a zombie processes, exiting the application".format(pid))
        sys.exit()
    else:
        if proc_name==runProc:
            if usr==getpass.getuser() or user: #(Included the bypass flag for user check)
                return [pid,pName,usr,cmdLine,status]
            else:
                print('Login user {loginUser} is different than the owner of the process i.e {ownUser}, set -U to True for bypassing user check'.format(loginUser=getpass.getuser(), ownUser=usr))
                logging.error("Login user : {loginUser} is not the owner {ownUser}".format(loginUser=getpass.getuser(), ownUser=usr))
                sys.exit()
        else:
            print('Incorrect Service Name')
            logging.error("Service Name entered is either incorrect or not running : {proc}".format(proc=proc_name))
            sys.exit()

def getPID(proc,user):
    '''Returns process related information after
        validating the PID passed by user'''
    procID=proc.strip()
    cmdLine=None
    pName=None
    pid=None
    usr=None
    status=None
    ppid=None
    try:
        if psutil.pid_exists(int(procID)) and int(procID)!=1:
            for p in psutil.process_iter(attrs=['pid','cmdline','name','username','status','ppid']):
                try:
                    if (p.info['pid']==int(procID)):
                        cmdLine=p.info['cmdline']
                        pName=p.info['name']
                        pid=p.info['pid']
                        usr=p.info['username']
                        status=p.info['status']
                        ppid=p.info['ppid']
                    else:
                        pass
                except (TypeError, IndexError) as e:
                    logging.error("Unexpected error occured while fetching the PID information contact Informatica Global Support")
                    pass
        else:
            pass
    except OverflowError:
        print("Entered PID {} is unrealistic, please enter a valid PID and try again ... exiting application".format(procID))
        logging.error("Entered PID {} is unrealistic".format(procID))
        sys.exit()
    # Validates if the process is defunct
    if status == 'zombie':
        print('Zombie Process detected {}: Parent process is dead. Kill and restart required, exiting application ...'.format(procID))
        logging.error("PID : {} detected as a zombie processes, exiting the application".format(procID))
        sys.exit()
    else:
        if int(procID)==pid:
            if usr==getpass.getuser() or user: #(Included the bypass flag for user check)
                return [pid,pName,usr,cmdLine,status,ppid]
            else:
                print('Login user {loginUser} is different than the owner of the process i.e {ownUser}, set -U to True for bypassing user check'.format(loginUser=getpass.getuser(), ownUser=usr))
                logging.error("Login user : {loginUser} is not the owner {ownUser}".format(loginUser=getpass.getuser(), ownUser=usr))
                sys.exit()
        else:
            print('Invalid PID')
            logging.error("Entered PID : {procID} is Invalid".format(procID=procID))
            sys.exit()

#Returns Informatica version
def getVersion(path):
    file_version=path+'/version.txt'
    with open(file_version,"r") as fd:
        for line in fd:
            if "Version" in line:
                version_num=line.split('=')[1].replace('"','')
    return version_num

#Returns lastest N files
def getLastN(path,n):
    cmd='ls -Art {p} | tail -n {n}'.format(p=path,n=n)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output.decode('utf-8').split("\n")[-2::-1]

def logDirectoryPath(infa_home):
    isptempSrc = getNodeLogDir(infa_home)
    node_log = isptempSrc+'/node.log'
    with open(node_log,"r") as fd:
        m = mmap.mmap(fd.fileno(), 0, prot=mmap.PROT_READ)
        index_string = m.rfind(b'CCM_10403')
        try:
            m.seek(index_string)
        except ValueError:
            print("Please collect the respective log files and share with Informatica Global Customer Support team")
        line = m.readline().decode("utf-8")
        log_directory_path = line[line.find("[") + 1:line.rfind("]")]
    return log_directory_path

#Returns node log directory path
def getNodeLogDir(path):
    version=getVersion(path)
    nodemeta_path=path+'/isp/config/nodemeta.xml'
    #Fetching node name from nodemeta.xml file. It is to append Node Name for tomcat logs directory.
    if version.startswith('1'):
        try:
            with open(nodemeta_path,"r") as nodemeta_file:
                for line in nodemeta_file:
                    if line.startswith('<domainservice'):
                        line_split = line.split(' ')
                        for word in line_split:
                            if 'systemLogDir' in word:
                                return unquote(word.split('=')[1].replace('"',''))
                            elif ('nodeName' in word) and (not 'systemLogDir' in word):
                                node_name=word.split('=')[1].replace('"','')
                                return path+'/logs/'+node_name
        except PermissionError:
            print("Permission denied while reading nodemeta.xml file, provide read priviledges and try again")
            logging.error("Failed to read nodemeta.xml file due to permission issue")
            sys.exit()
        except:
            print("Error occured while reading nodemeta.xml file")
            logging.error("Failed to read nodemeta.xml file due to permission issue")
            sys.exit()
    else:
        return path+'/tomcat/logs'

#Fetch RS name using pmserver pid
def getRS(pid,infa_home):
    server_home=infa_home+'/server/bin/'
    my_env = os.environ.copy()
    my_env['LD_LIBRARY_PATH']= os.pathsep.join([server_home,my_env["LD_LIBRARY_PATH"]])
    my_env['INFA_HOME']=infa_home
    my_env['INFA_DOMAINS_FILE']=infa_home+'/domains.infa'
    for process in psutil.process_iter():
        process_info=process.as_dict(attrs=['name','cmdline','pid','ppid'])
        if process_info['pid']==pid and process_info['name']=='pmserver':
            domName=convBase64(process_info['cmdline'][1],False)
            isName=convBase64(process_info['cmdline'][2],False)
            break
    fetchRSCmd=infa_home+'/server/bin/pmcmd getserviceproperties -sv '+ isName + ' -d ' + domName
    process = subprocess.Popen(fetchRSCmd,env=my_env,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    stdout = output.decode('utf-8').split("\n")
    for line in  stdout:
        if line.startswith("Integration Service is connected to repository service"):
            rsName=line[line.index('[')+1:line.index(']')]
            return rsName

#Fetch all the pids of the parent processes
def getRecursive(pid,infa_home):
    pidDict={
    'nodeJava':[None,False],
    'javaChild':[None,False],
    'AdminConsole':[None,False],
    'pmrepagent':[None,False],
    'pmserver':[None,False],
    'pmdtm':[None,False]
    }
    inProc=getPID(str(pid),True)
    adminPid=getProcess('AdminConsole', True)[0]
    nodePid=getPID(str(adminPid), True)[5]
    pmrepagentPid=None
    pmserverPid=None
    pmdtmPid=None
    if inProc[1]=='pmdtm':
        pmdtmPid=inProc[0]
        pmserverPid=inProc[5]
        pmrepagentPid=getProcess(getRS(pmserverPid, infa_home),True)[0]
        pidDict['nodeJava']=[nodePid,True]
        pidDict['AdminConsole']=[adminPid,True]
        pidDict['pmrepagent']=[pmrepagentPid,True]
        pidDict['pmserver']=[pmserverPid,True]
        pidDict['pmdtm']=[pmdtmPid,True]
    elif inProc[1]=='pmserver':
        pmserverPid=inProc[0]
        pmrepagentPid=getProcess(getRS(pmserverPid, infa_home),True)[0]
        pidDict['nodeJava']=[nodePid,True]
        pidDict['AdminConsole']=[adminPid,True]
        pidDict['pmrepagent']=[pmrepagentPid,True]
        pidDict['pmserver']=[pmserverPid,True]
    elif inProc[1]=='pmrepagent':
        pmrepagentPid=inProc[0]
        pidDict['nodeJava']=[nodePid,True]
        pidDict['AdminConsole']=[adminPid,True]
        pidDict['pmrepagent']=[pmrepagentPid,True]
    elif inProc[0]==adminPid:
        pidDict['nodeJava']=[nodePid,True]
        pidDict['AdminConsole']=[adminPid,True]
    elif inProc[1]=='java' and nodePid==inProc[5]:
        pidDict['nodeJava']=[nodePid,True]
        pidDict['javaChild']=[inProc[0],True]
    elif inProc[0]==nodePid:
        pidDict['nodeJava']=[nodePid,True]
    else:
        pass
    return pidDict

'''Collects all the system and process related artifacts,
zips and stores in the pwd'''
def gather(infa_home,pid,pName,user,itr,dl,jdkHome,colPath,rec,runSys,strace):

    #generic
    sPid=str(pid)
    path=colPath
    # Command related
    app_dir_sys=path+'/sys'
    app_dir_proc=path+'/proc/'+pName+'_'+sPid

    # SAR related
    sarSrc='/var/log/sa'
    sarDst=app_dir_sys+'/sar'
    sarList=getLastN(sarSrc,6)

    # messages related
    msgSrc='/var/log'
    msgDst=app_dir_sys
    msgFile=['messages']

    # Source Paths for Infa Files
    ispSrc=logDirectoryPath(infa_home)
    csmSrc=infa_home+'/tomcat/webapps/csm/output'
    nodeSrc=getNodeLogDir(infa_home)
    servAdminSrc=nodeSrc+'/services/AdministratorConsole'
    servWshSrc=nodeSrc+'/services/WebServiceHub'

    # Target Paths for Infa Files
    confPath=path+'/infa_files/config'
    ispPath=path+'/infa_files/ISPLogs'
    csmPath=path+'/infa_files/CSM'
    nodePath=path+'/infa_files/nodeLogs'
    servAdminPath=nodePath+'/services/AdministratorConsole'
    servWshPath=nodePath+'/services/WebServiceHub'

    # Object Lists for Infa Files
    ispList=getLastN(ispSrc,2)
    csmList=getLastN(csmSrc,6)
    nodeList=['catalina.out','catalina_shutdown.out','exceptions.log','ispLogs.log','node_jsf.log','node.log','ispLogs.log']
    servAdminList=getLastN(servAdminSrc, 6)
    servWshList=getLastN(servWshSrc, 6)

    procDict={
    #process level collection
    #<command_name>:[ <Type(Process/System)>, <Iterable?>, <command>, <0-Common, 1-Java, 2-Native>,<Concatenate?>]
        'top_p':['P', True, 'top -bHp {pid} -n 1 -d 1 >  top_{pid}_{itr}.out',0,True],
        'pmap':['P', True, 'pmap -x {pid} > pmap_{pid}_{itr}.out',0,False],
        'netstat_p':['P', True, 'netstat -peano | grep {pid} > netstat_{pid}_{itr}.out',0,True],
        'lsof_p':['P', True, 'lsof -p {pid} > lsof_{pid}_{itr}.out',0,False],
        'pmstack':['P', True, '{infaHome}/tools/debugtools/pmstack/pmstack -p {pid}',2,False],
        'pstack':['P', True, 'pstack {pid} > pstack_{pid}_{itr}.out',2,False],
        'jstack':['P', True, '{jdkHome}/jstack -l {pid} > jstack_{pid}_{itr}.out', 1,False],
    #Putting strace in the end as it bring 10s delay
        'strace':['P', False, 'timeout {strace}s strace -fF -tT -o strace_{pid}.out -p {pid} 2> /dev/null',0,False]
    }

    sysDict={
    #system level collection
    #<command_name>:[ <Type(Process/System)>, <Iterable?>, <command>, <0-Common, 1-Java, 2-Native>,<Concatenate?>]
        'vmstat':['S', True, 'vmstat > vmstat_{itr}.out',0,True],
        'ulimit':['S', False, 'ulimit -a > ulimit.out',0,False],
        'top_s':['S', True, 'top -b -d 1 -n 1 >  top_{itr}.out',0,True],
        'netstat_s':['S', True, 'netstat -peaon > netstat_{itr}.out',0,True],
        'iostat':['S', True, 'iostat > iostat_{itr}.out',0,True],
        'lsof_s':[ 'S', False, 'lsof -u {usr} > lsof_{usr}.out',0,False],
        'ps-ef':[ 'S', True, 'ps -ef > ps_{itr}.out',0,True],
    }


    #Objects to copy files /proc/<PID> directory
    ppid_src='/proc/'+sPid
    ppid_dst=app_dir_proc+'/proc_pid_files'
    ppid_fileList=('stat','status','cmdline','statm',
                    'environ','maps', 'wchan','stack',
                    'smaps','sessionid','loginuid','io',
                    'mountstats','mounts','mountinfo',
                    'sched','limits','numa_maps','comm')

    #Dictionary for the infa related objects
    logDict={
    #<fileType>:[<srcPath>,<dstPath>,<[objName]>]
    # Config files:
        'config1':[infa_home,confPath,['version.txt','domains.infa']],
        'config2':[infa_home+'/isp/config',confPath,['nodemeta.xml']],
        'config3':[infa_home+'/server/bin',confPath,['ebfHistory.info']],
        'config4':[infa_home+'/isp/bin',confPath,['nodeoptions.xml']],
        'config5':[infa_home+'/tomcat/conf',confPath,['web.xml','server.xml']],
        'config6':[infa_home+'/tomcat/temp',confPath,['tomcat_envvars.txt','envvars.txt']],
    # isp folders:
        'isp':[ispSrc,ispPath,ispList],
    # csm files:
        'csm':[csmSrc,csmPath,csmList],
    # node logs:
        'nodeLogs':[nodeSrc,nodePath,nodeList],
    # Service logs:
        'servAdmin':[servAdminSrc,servAdminPath,servAdminList],
        'servWsh':[servWshSrc,servWshPath,servWshList]
    }


    def exec_proc(dict,itr):
        for i in dict:
            cmd=dict[i][2].format(pid=sPid,itr=itr+1,usr=user,infaHome=infa_home,jdkHome=jdkHome,strace=strace)
            path='{}/{}'.format(app_dir_proc,i) if dict[i][0]=='P' else '{}/{}'.format(app_dir_sys,i)
            # if process is non java(adminconsole, nodeJava added for preserving the name) other than pmdtm then dont collect jstack
            # if process is java(adminconsole, nodeJava added for preserving the name) then dont collect pstack and pmstack
            # if process is not iterative and value of itr is more than 1 then skip
            if (dict[i][3]==1 and pName not in ['java','pmdtm','AdminConsole','nodeJava']) or (dict[i][3]==2 and pName in ['java','AdminConsole','nodeJava']) or (itr > 0 and not dict[i][1]):
                pass
            else:
                # Create directories for the first time only
                if (itr==0):
                    try:
                        os.makedirs(path)
                    except PermissionError:
                        print('No permissions to create directory at {} ... exiting application ..'.format(path))
                        logging.error("Failed to create directory {} due to permission issue".format(path))
                        sys.exit()
                    except OSError:
                        print ('Creation of the directory {} failed ... exiting application'.format(path))
                        logging.error("Failed to create directory {}".format(path))
                        sys.exit()
                    else:
                        print ('Successfully created the directory: {}'.format(path))
                if dict[i][0]=='P':
                    print('Collecting output for {cmd} for Process : {proc} with PID : {pid} at {path}'.format(cmd=i, proc=pName.upper(), pid=sPid, path=path))
                    logging.info("Iteration {itr} for {proc} - Starting - {cmd} collection".format(itr=itr+1,proc=pName,cmd=i))
                else:
                    print('Collecting output for {cmd} at {path}'.format(cmd=i, path=path))
                    logging.info("Iteration {itr} Starting - {cmd} sys command collection".format(itr=itr+1,proc=pName,cmd=i))
                os.environ['INFA_HOME'] = infa_home
                run=subprocess.Popen(cmd,shell=True,cwd=path,close_fds=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output,error=run.communicate()
                if error!=b'':
                    logging.error("ERROR {error} caught while running : {cmd} contact Informatica Global Support".format(error=error,cmd=i))
                elif error==b'':
                    logging.info("Successfully collected {cmd} ouput for {proc}".format(cmd=i,proc=pName))


    def cpy(src_path,dst_path,obj):
        if os.path.exists(os.path.join(dst_path)):
            pass
        else:
            os.makedirs(dst_path)
        for i in obj:
            src_obj=src_path+'/'+ i
            dst_obj=dst_path+'/'+i
            try:
                if os.path.isfile(src_obj):
                    copy_file(src_obj, dst_obj)
                    print('Successfully copied {file} to {dest}'.format(file=src_obj, dest=dst_obj))
                    logging.info('Successfully copied {file} to {dest}'.format(file=src_obj, dest=dst_obj))
                else:
                    copy_tree(src_obj, dst_obj)
                    print('Successfully copied {file} to {dest}'.format(file=src_obj, dest=dst_obj))
                    logging.info('Successfully copied {file} to {dest}'.format(file=src_obj, dest=dst_obj))
            except:
                print("File not copied : Check if file : \"{obj}\" exists or has sufficient permissions".format(obj=src_obj))
                logging.error("File not copied : Check if file : \"{obj}\" exists or has sufficient permissions".format(obj=src_obj))
                pass

    def concatIter(dict,itr):
        for i in dict:
            path=path='{}/{}'.format(app_dir_proc,i) if dict[i][0]=='P' else '{}/{}'.format(app_dir_sys,i)
            cmd='cat * > all_{cmd}.out'.format(cmd=i)
            if dict[i][4] and itr>1:
                run=subprocess.Popen(cmd,shell=True,cwd=path,close_fds=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output,error=run.communicate()
                if error!=b'':
                    logging.error("Issues occured while running :{cmd}".format(cmd=cmd))
            else:
                pass

    '''Process level collections'''
    logging.info('Initializing process level collection for {proc} process with pid {pid}'.format(proc=pName,pid=pid))
    #Start Running the proc level commands
    for i in range(itr):
        '''if delay is less than the strace runtime for the first run then ignore the value
        if delay is higher than the strace runtime then substract dl with strace runtime value
        else for the regular run keep the delay as it is'''
        if (dl > strace and i==0):
            delay= (dl-strace)
        elif (strace >= dl and i==0):
            delay=0
        else:
            delay=dl
        strcDl=strace if i==0 else 0
        details=" Gathering logs and traces for the iteration :{} / {} with the delay of {} secs ".format(i+1,itr,delay+strcDl)
        print('\n', details.center(100, '*'), '\n')
        exec_proc(procDict,i)
        if itr>1:
            time.sleep(delay)

    #Concatenating all the iterative output files:
    concatIter(procDict,itr)

    #Start Copying the proc files
    print("\n********Copying files from /proc/{pid}******** \n".format(pid=sPid))
    cpy(ppid_src,ppid_dst,ppid_fileList)

    logging.info('Completed process level collection for {proc} process with pid {pid}'.format(proc=pName,pid=pid))
    '''End of process level collections'''

    '''System level collection'''
    logging.info('Initializing system level collection for {itr} iterations with delay of {delay} secs'.format(itr=itr,delay=dl))
    if (rec and runSys) or rec==False:
        #Start Running the sys level commands
        for i in range(itr):
            details=" Gathering logs and traces for the iteration :{} / {} with the delay of {} secs ".format(i+1,itr,dl)
            print('\n', details.center(100, '*'), '\n')
            exec_proc(sysDict,i)
            if itr>1:
                time.sleep(dl)

        #Concatenating all the iterative output files:
        concatIter(sysDict,itr)

        #Collect SAR file:
        print("\n********Copying sar files from {}******** \n".format(sarSrc))
        cpy(sarSrc,sarDst,sarList)

        #Collect messages file:
        print("\n********Copying messages file from {}******** \n".format(msgSrc))
        cpy(msgSrc,msgDst,msgFile)

        #Start Copying the Infa files
        for i in logDict:
            if 'config' in i:
                print("\nCopying config files from {path} : {files} \n".format(files=logDict[i][2],path=logDict[i][0]))
            elif i =='isp':
                print("\n********Copying ISP logs******** \n")
            elif i =='csm':
                print("\n********Copying CSM logs******** \n")
            elif i == 'nodeLogs':
                print("\n********Copying Node logs******** \n")
            else:
                print("\n********Copying Service logs******** \n")

            if os.path.exists(logDict[i][0]):
                cpy(logDict[i][0],logDict[i][1],logDict[i][2])
            else:
                pass
    else:
        pass
    logging.info('Completed system level collection for {itr} iterations with delay of {delay} secs\n'.format(itr=itr,delay=dl))
    '''End of system level collections'''

#Signal Hangle
class GracefulKiller:
  kill_now = False
  def __init__(self):
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)
    signal.signal(signal.SIGTSTP, self.exit_gracefully)

  def exit_gracefully(self,signum, frame):
    self.kill_now = True
    raise KeyboardInterrupt


if __name__ == '__main__':
    killer= GracefulKiller()
    while not killer.kill_now:
        try:
            mainRun()
        except KeyboardInterrupt:
            print("Aborted")
        except Exception:
            traceback.print_exc(file=sys.stdout)
        sys.exit(0)
