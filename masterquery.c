/*
 *
 * This is a query tool for steam servers, based on A2S_INFO protocal
 * 
 * Build dependency: none
   (it is tested on CentOS's gcc 10.3.1)

 * Compile it like this:
   gcc masterquery.c -lpthread -o masterquery
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <getopt.h>


/*   =======================================    */

/*
*   declear part (*.h)  
*/

#define MAXDATASIZE 1400
#define MAXSERVER 128

/*type define*/

struct valveServInfo
{
    char ipv4[16];
    int port;
    int status;
    char hostname[64];
    char map[32];
    int players;
    int slots;
    int ticks;
    char playername[8][32];
    int playerscore[8];
    double duration[8];
};

struct valveServList
{
    int length;
    int survive;
    int allplayers;
    int index[MAXSERVER];
    struct valveServInfo server[MAXSERVER];
};

/*global var declear*/

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct commonDataPack
{
    struct valveServInfo *pserver;
} commonData4thread;

struct masterqueryGlobalVar_t
{
    int opt_logon;
    int opt_verbose;
    int opt_thread;
    int opt_web;
    int opt_footer; 
    int opt_header;
} masterGlobalVar;

/*function declear*/

int sscanIp2srvInfo(char *addrport, struct valveServInfo *pserver);
int fscanIp2srvList(FILE *fp, struct valveServList *pservList);

int DNSquery (char* hostname);
int A2S_INFO (struct valveServInfo *pserver);

void * query_thread();
int queryList_mt(struct valveServList *pservList, int thread_n);

int arcSimSort(int head, int tail, int* index, int* data);
int arcPivotSort(int head, int tail, int* index, int* data);
int arcQuickSort(int head, int tail, int* index, int* data);

int fprintHTML_header_default(FILE *fp);
int fprintHTML_content(FILE *fp, struct valveServList *pservList);
int fprintHTML_footer_default(FILE *fp);
int fprintfHTML_DIY(FILE *fp, FILE *source);

int settleJsPath(char *statusPath, char *htmlPath);
int updateStatusJS(FILE *fp, struct valveServList *pservList);

int version_print(char *pName);
int usage_print(char *pName);

/*
*   end of declear part
*/


/*   =======================================    */


/*
*   define part (*.c)
*/

int sscanIp2srvInfo(char *addrport, struct valveServInfo *pserver) {
    char *server_IP, *getport, *gettick, *input_option=strdup(addrport);
    server_IP = strsep(&input_option,":");
    getport = strsep(&input_option,"T");
    gettick = strsep(&input_option,"@");
    free(input_option);
    sprintf(pserver[0].ipv4,"%s",server_IP);
    pserver[0].port=(getport==NULL)?27015:atoi(getport);
    pserver[0].ticks=(gettick==NULL)?100:atoi(gettick);
    return 0;
}

int fscanIp2srvList(FILE *fp, struct valveServList *pservList) {
    int pf, length;
    char addrport[64];

    pservList[0].length=0; pf=0;
    while(fscanf(fp,"%s",addrport)>0 && pf<MAXSERVER){
        sscanIp2srvInfo(addrport,&pservList[0].server[pf]);
        pf++;
    }
    pservList[0].length=pf;
    pservList[0].survive=0;
    pservList[0].allplayers=0;

    /*initiate the index of the server list*/
    length=pf;
    for(pf=0;pf<length;pf++){
        pservList[0].index[pf]=pf;
    }
    return 0;
}

int DNSquery (char* hostname) {
    char  *ptr;
    struct hostent *hostptr;
    if ( (hostptr = gethostbyname(hostname)) == NULL)
        {
            if(masterGlobalVar.opt_logon){
                fprintf(stderr,"DNS query failure: unable to solve %s\n",hostname);
            }
            return -1;
        }
        if(hostptr->h_addrtype == AF_INET)
        {
            inet_ntop(hostptr->h_addrtype, *(hostptr->h_addr_list), hostname, 64);
        }else{
                if(masterGlobalVar.opt_logon){
                    fprintf(stderr, "DNS query failure: unknown address type (%s)\n",hostname);
                }
        return -1;
        }
    return 0;
}

int A2S_INFO (struct valveServInfo *pserver) {
    float time_sec;
    int sockfd, num, pf, pt, nameLen=0, min=0, hr=0, score=0;
    unsigned char buf[2048],challenge[9],player_request[9],*p_time = (unsigned char*)&time_sec;
    unsigned char info_request[29]={0xFF,0xFF,0xFF,0xFF,0x54,0x53,0x6F,0x75,0x72,0x63,0x65,0x20,0x45,0x6E,0x67,0x69,0x6E,0x65,0x20,0x51,0x75,0x65,0x72,0x79,0x00,0xff,0xff,0xff,0xff};

    struct sockaddr_in serverSock;

    /*Define protocol as UPD and initiate the socket*/
    if((sockfd=socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
	    pserver[0].status=-1;
        return -1;
    }else{
	    pserver[0].status=0;
    }
    bzero(&serverSock, sizeof(serverSock));
    serverSock.sin_family = AF_INET;
    serverSock.sin_port = htons(pserver[0].port);
    if((serverSock.sin_addr.s_addr = inet_addr(pserver[0].ipv4))==-1)
    {
        if(DNSquery(pserver[0].ipv4)==-1){
			pserver[0].status=-1;
			return -1;
		}
        serverSock.sin_addr.s_addr = inet_addr(pserver[0].ipv4);
    }

    /*Set timeout limit to avoid stuck at recv() process*/
    struct timeval timeout;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
    {
		pserver[0].status=-1;
        return -1;
    }

    if(connect(sockfd, (struct sockaddr *)&serverSock, sizeof(serverSock)) == -1)
    {
		pserver[0].status=-1;
        return -1;
    }

    /*Send info request to Valve server*/
    send(sockfd, info_request, 29, 0);
    if((num = recv(sockfd, buf, MAXDATASIZE, 0)) == -1)
    {
		pserver[0].status=-1;
        return -1;
    }

    /*Sometime need to resend the request with CHALLENGE number*/
    if(buf[4] & 0x41){
	    info_request[25]=buf[5];info_request[26]=buf[6];info_request[27]=buf[7];info_request[28]=buf[8];
	    send(sockfd, info_request, 29, 0);
        info_request[25]=0xff;info_request[26]=0xff;info_request[27]=0xff;info_request[28]=0xff;
	    if((num = recv(sockfd, buf, MAXDATASIZE, 0)) == -1)
    	{
		    pserver[0].status=-1;
        	return -1;
    	}
    }

    /*Extract server basic info*/
    for(pf=6;;)
    {
		pt=0;
        while(buf[pf]!=0x00){
			pserver[0].hostname[pt]=buf[pf++];
			pt=pt<63?pt+1:pt;
		}
		pserver[0].hostname[63]=0;
        pf++;pt=0;
        while(buf[pf]!=0x00){
			pserver[0].map[pt]=buf[pf++];
			pt=pt<31?pt+1:pt;
		}
        pf++;
        pserver[0].map[31]=0;
        while(buf[pf++]!=0x00);while(buf[pf++]!=0x00);
        pf+=2;
		pserver[0].players=buf[pf];
		pserver[0].slots=buf[pf+1];
        break;
    }

    /*Send player request to Valve server*/
    for(pf=0;pf<9;pf++) player_request[pf]=0xFF;
    player_request[4]=0x55;
    send(sockfd, player_request, 9, 0);

    /*Receive challenge code from server*/
    if((num = recv(sockfd, buf, MAXDATASIZE, 0)) == -1)
    {
		pserver[0].players=0;
		pserver[0].status=-1;
        return -1;
    }

    /*Reply the challenge*/
    for(pf=0;pf<num;pf++) challenge[pf]=buf[pf];
    challenge[4]=player_request[4];
    send(sockfd, challenge, 9, 0);

    /*Receive Players info*/
    if((num = recv(sockfd, buf, MAXDATASIZE, 0)) == -1)
    {
		pserver[0].players=0;
		pserver[0].status=-1;
        return -1;
    }
    
    /*Decode the bytes, buf[5] is total players quantity*/
    if(buf[5]>0x00)
    {
        pf=6;nameLen=0;pt=0;
        while(pf<num)
        {   
            if(buf[pf]==0x00) pf++;
            /*extract player's name*/
            while(buf[pf]!=0x00)
            {
                pserver[0].playername[pt][nameLen]=(buf[pf++]);
                nameLen=nameLen<31?nameLen+1:nameLen;
            }
			pserver[0].playername[pt][31]=0;
            /*The loading players would not be included in the UDP pack, add an identical name to them manually*/
            if(nameLen==0) {sprintf(pserver[0].playername[pt],"Loading");}

            /*extract score*/
            score=buf[++pf];pf+=4;
			pserver[0].playerscore[pt]=score;

            /*extract time as float*/
            p_time[0]=buf[pf];p_time[1]=buf[pf+1];p_time[2]=buf[pf+2];p_time[3]=buf[pf+3];
			pserver[0].duration[pt]=time_sec;
            pf+=4;nameLen=0;pt++;
			if(pt>7) break;
        }
    }
	pserver[0].status=0;
    close(sockfd);
    return 0;
}

void * query_thread(){
    struct valveServInfo *pserver;
    pthread_mutex_lock(&mutex);
    pserver=commonData4thread.pserver;
    pthread_mutex_unlock(&mutex);
    A2S_INFO(pserver);
    if(masterGlobalVar.opt_verbose){
        fprintf(stdout,"%s:%d    status: %d\n",pserver[0].ipv4,pserver[0].port,pserver[0].status);
    }
    return 0;
}

/*single thread implementation*/
int queryList_st(struct valveServList *pservList){
    int pf=0, p, th_s=0, indexLen=pservList[0].length;
    while (pf<indexLen){
        commonData4thread.pserver = &pservList[0].server[pf];
        A2S_INFO(commonData4thread.pserver);
        pf++;
    }
    /*Count for survive servers and total players*/
    for(pf=0;pf<indexLen;pf++){
        if(!pservList[0].server[pf].status){
            pservList[0].survive++;
            pservList[0].allplayers+=pservList[0].server[pf].players;     
        }
    }
    return 0;
}

int queryList_mt(struct valveServList *pservList, int thread_n){
    pthread_t query_pid[16];
    int pf=0, p, th_s=0, indexLen=pservList[0].length;
    while (pf<indexLen){
        for (th_s=0; th_s<thread_n && pf<indexLen; th_s++){
            commonData4thread.pserver = &pservList[0].server[pf];
            while(pthread_create(query_pid+th_s, NULL, query_thread, NULL)){
                if(masterGlobalVar.opt_logon){
                    fprintf(stderr,"thread create failed, retrying.\n");
                }
                usleep(50000);
            }
            ++pf;
            usleep(50000);
        }
        /*Wait4Join*/
        for(p=0;p<th_s;p++){
            pthread_join(query_pid[p],NULL);
        }
    }
    /*Count for survive servers and total players*/
    for(pf=0;pf<indexLen;pf++){
        if(!pservList[0].server[pf].status){
            pservList[0].survive++;
            pservList[0].allplayers+=pservList[0].server[pf].players;     
        }
    }
    
    return 0;
}

int fprint_console(struct valveServList *pservList) {
    int pf, p, cnt, players, hr, min;
    const int indexLen=pservList[0].length;
    const int survive=pservList[0].survive;
    const int *index=pservList[0].index;
    double duration;

    for (pf=indexLen-1;pf>-1;pf--){
        players=pservList[0].server[index[pf]].players;
        /*players=players<8?players:8;*/
        players=players>0?players:0;

        if(pservList[0].server[index[pf]].status)
        {
            if(masterGlobalVar.opt_logon){
                fprintf(stderr, "%s:%d timeout!\n", pservList[0].server[index[pf]].ipv4, pservList[0].server[index[pf]].port);
            }
            continue;
        }

    //basic info
        fprintf(stdout, "%s @ %dfps\n%s:%d\t%s\t%d/%d\n",
        pservList[0].server[index[pf]].hostname,
        pservList[0].server[index[pf]].ticks,  
        pservList[0].server[index[pf]].ipv4, 
        pservList[0].server[index[pf]].port, 
        pservList[0].server[index[pf]].map,
        pservList[0].server[index[pf]].players, 
        pservList[0].server[index[pf]].slots);

        /*player info*/
        for(p=0;p<players;p++){
            fprintf(stdout, "  %s\t", pservList[0].server[index[pf]].playername[p]);
		/*time and score*/
            duration=pservList[0].server[index[pf]].duration[p];
		    hr=duration/3600;
            min=(duration-hr*3600)/60;
		    if(hr) fprintf(stdout, "%dh", hr);
		    if(min) fprintf(stdout, "%dm", min);
		    fprintf(stdout, "%.0fs\t", duration-3600*hr-60*min);
		    fprintf(stdout, "%d\n", pservList[0].server[index[pf]].playerscore[p]);
	    }
	    fprintf(stdout, "\n");

    /*end of detail info*/
    }

    fprintf(stdout,"\n-[ status ]-\nservers up:\033[32m %d\033[0m\nlost hosts:\033[31m %d\033[0m\nplayers on:\033[36m %d\033[0m\n",
    survive, indexLen-survive, pservList[0].allplayers);

    return 0;
}

int fprintHTML_content(FILE *fp, struct valveServList *pservList) {
    int pf, p, cnt, players, hr, min;
    const int indexLen=pservList[0].length;
    const int survive=pservList[0].survive;
    const int *index=pservList[0].index;
    double duration;

    for (pf=indexLen-1;pf>-1;pf--){
        players=pservList[0].server[index[pf]].players;
        players=players<8?players:8;
        players=players>0?players:0;

        if(pservList[0].server[index[pf]].status)
        {
            if(masterGlobalVar.opt_logon){
                fprintf(stderr, "%s:%d timeout!\n", pservList[0].server[index[pf]].ipv4, pservList[0].server[index[pf]].port);
            }
            continue;
        }

    //cache server basic info html (basic info table)
	    fprintf(fp, "<div class=\"serverinfo\"><table><tbody>\n");
	    if(players){
		    if(pservList[0].server[index[pf]].slots>players){
			    if(players<4){
				    fprintf(fp, "<tr class=\"hostinfo nicehost\">");
			    }else{
				    fprintf(fp, "<tr class=\"hostinfo spechost\">");
			    }
		    }else{
			    fprintf(fp, "<tr class=\"hostinfo fullhost\">");
		    }
	    }else{
		    fprintf(fp, "<tr class=\"emptyhost\">");
	    }

        /*insert double click javascript*/
        fprintf(fp, "<td colspan=\"2\" class=\"hostname\" ondblclick=\"cpIp2Clip(\'%s:%d\');\"><span class=\"blockgreen\"></span>%s</td><td class=\"slotinfo\"><span class=\"slotingame\">%d</span>/%d</td></tr>\n",pservList[0].server[index[pf]].ipv4,pservList[0].server[index[pf]].port,pservList[0].server[index[pf]].hostname,pservList[0].server[index[pf]].players,pservList[0].server[index[pf]].slots);
	    fprintf(fp, "</tbody></table>\n");
    /*end of basic info table*/

    /*cache map tickrate info html (detail info table)*/
	    fprintf(fp, "<table class=\"playertable\"><tbody>\n");
        fprintf(fp, "<tr class=\"headrow\"><td class=\"map\">%s</td><td class=\"tickrate\">%dfps</td><td><a href=\"steam://connect/%s:%d\" target=\"_blank\" class=\"joingame\">Join</a></td></tr>\n",pservList[0].server[index[pf]].map,pservList[0].server[index[pf]].ticks,pservList[0].server[index[pf]].ipv4,pservList[0].server[index[pf]].port);

        /*cache player info*/
        for(p=0;p<players;p++){
		    fprintf(fp, "<tr class=\"playerinfo\">");
            fprintf(fp, "<td class=\"playername\">%s</td>", pservList[0].server[index[pf]].playername[p]);
		/*time and score*/
            duration=pservList[0].server[index[pf]].duration[p];
		    hr=duration/3600;
            min=(duration-hr*3600)/60;
            fprintf(fp, "<td>");
		    if(hr) fprintf(fp, "%dh", hr);
		    if(min) fprintf(fp, "%dm", min);
		    fprintf(fp, "%.0fs</td>", duration-3600*hr-60*min);
		    fprintf(fp, "<td>%d</td>", pservList[0].server[index[pf]].playerscore[p]);
		    fprintf(fp, "</tr>");
	    }
        fprintf(fp, "\n<tr><td colspan=\"3\" class=\"location\">Location: <span id=\"AS%d\">unknown</span></td></tr>\n",index[pf]);
	    fprintf(fp, "</tbody></table>\n</div>\n");

    /*end of detail info table*/
    }

    /*Insert javascript to get ip location, the script will call a js function that changes the html content*/
    fprintf(fp, "<script>\n");
    for(cnt=0,pf=indexLen; cnt<survive; pf--,cnt++){
        fprintf(fp, "labelIp(\'AS%d\',\'%s\');\n",index[pf-1],pservList[0].server[index[pf-1]].ipv4);
	}
	fprintf(fp, "\n</script>\n");

    return 0;
}

int fprintHTML_header_default(FILE *fp) {
    
    /*Print HTTP doctype and meta*/
    fprintf(fp,"<!DOCTYPE html>\n<html>\n");
    fprintf(fp,"<head>\n<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\">\n<meta name=\"viewport\" content=\"width=500, initial-scale=0.7, maximum-scale=2.0, minimum-scale=0.7\">\n<meta http-equiv=\"cache-control\" content=\"max-age=90\">\n<meta name=\"referrer\" content=\"no-referrer\">\n");
    fprintf(fp,"<title>AnneHappy Servers</title>\n<script type=\"text/javascript\" src=\"js/ip.js\"></script>\n");
    fprintf(fp,"<link rel=\"icon\" href=\"gamma.png\" type=\"image/png\">\n");
	fprintf(fp,"\t<link rel=\"stylesheet\" href=\"css/serverlist.css\">\n");
    fprintf(fp,"</head>\n");

    /*Print body marker*/
    fprintf(fp,"<body class=\"main\">");

    /*Some more DIY info before the server's info content*/
    fprintf(fp,"<h2 id=\"title\">Anne Happy Group Server List</h2><br />\n");
    fprintf(fp,"<p class=\"date\" id=\"timeStamp\"></p><br />\n");
    fprintf(fp,"<div class=\"summary\">(<span id=\"jamhostCt\"></span>) servers up: <span id=\"serversOn\">0</span>players in-game: <span id=\"playersOn\">0</span></div>\n");
    fprintf(fp,"<div class=\"tips\">\n\t<div class=\"tips_head\"><span class=\"tips_head_wd\">Your favorite server not found?</span></div>\n<ul class=\"tips_hint\">\n<li>You may leave a comment in the <a href=\"https://arxiv.cloud/\">home page</a> to tell us the server's IP:port. We'll check and add it to the query list later.</li><li>The malfunction servers will not display in the list. Often, they're just under DDoS attack.</li>\n</ul></div>\n");
	fprintf(fp,"<span id=\"dblclickInfo\" onclick=\"document.getElementById(\'dblclickInfo\').innerHTML=\'\';\"></span>\n<script>\n\tfunction cpIp2Clip(ip){\n\t\tnavigator.clipboard.writeText(ip);\n\t\tdocument.getElementById(\'dblclickInfo\').innerHTML=ip+\' is copied to clipboard\';\n}\n</script>\n");
    return 0;
}

int fprintHTML_footer_default(FILE *fp) {
	fprintf(fp,"<br />\n<div class=\"footer\"><pre>This L4D2 CO-OP plugin is developed by <b>Anne</b>.\nUnzip the <a href=\"https://github.com/Caibiii/AnneServer/\">AnneHappy plugin</a> to your dedicated server and join us!\nThank <b>HoongDou</b> for updating the script and <a href=\"https://www.hoongdou.com/index.php/2021/05/22/anne/\">README</a>.</pre></div>\n");
    fprintf(fp,"\n<script src=\"js/status.js\"></script>\n");
    fprintf(fp,"\n</body>\n</html>\n");
	return 0;
}

int fprintfHTML_DIY(FILE *fp, FILE *source) {
    char readlineHTML[4096];
    while(fgets(readlineHTML, 4096, source)!=NULL){
        fputs(readlineHTML, fp);
    }
    return 0;
}

int settleJsPath(char *statusPath, char *htmlPath) {
    int pf=0, cend=0;
    while(htmlPath[cend]){cend++;}
    while(htmlPath[cend]!='/' && cend>0){cend--;}
    if(htmlPath[cend]!='/'){cend=-1;}
    for(pf=0;pf<cend+1;pf++){
        statusPath[pf]=htmlPath[pf];
    }
    statusPath[pf]=0;
    strcat(statusPath,"js");
    if(access(statusPath,0)){
        if(mkdir(statusPath,0744)){
            fprintf(stderr,"can not create directory %s\n",statusPath);
            return -1;
        }else{
            fprintf(stdout,"create directory \033[33m%s\033[0m\n",statusPath);
        }
    }
    strcat(statusPath,"/status.js");
    return 0;
}

int updateStatusJS(FILE *fp, struct valveServList *pservList) {
    char str_time[128];
    time_t var_time_t=time(NULL);
    const struct tm *ptr_local_time=localtime(&var_time_t);

    strftime(str_time,128,"%B %d %Y <b class=\"time\">%H:%M</b> %Z",ptr_local_time);
    fprintf(fp,"document.getElementById(\'playersOn\').innerHTML=\'%d\';\n",pservList[0].allplayers);
    fprintf(fp,"document.getElementById(\'serversOn\').innerHTML=\'%d\';\n",pservList[0].survive);
    fprintf(fp,"document.getElementById(\'jamhostCt\').innerHTML=\'%d\';\n",pservList[0].length-pservList[0].survive);
    fprintf(fp,"document.getElementById(\'timeStamp\').innerHTML=\'%s\';\n",str_time);
    return 0;
}

int arcSimSort(int head, int tail, int* index, int* data) {    
    int pf, spf=0, unsort, swap;
    for(unsort=head;unsort<tail+1;unsort++)
    {
    	pf=unsort;spf=unsort;
    	while(pf<tail+1)
    	{
    		spf=data[index[pf]]<data[index[spf]]?pf:spf;
    		pf++;
    	}
    	swap=index[spf];
    	index[spf]=index[unsort];
    	index[unsort]=swap;
    }
    return 0;
}

int arcPivotSort(int head, int tail, int* index, int* data) {
    int pivot, swap;
    int phead=head, ptail=tail;
    int dhead=data[index[phead]], dmidd=data[index[(phead+ptail)/2]], dtail=data[index[ptail]];
    pivot=((dhead-dmidd)*(dmidd-dtail)>0)?dmidd:((dmidd-dhead)*(dhead-dtail)>0?dhead:dtail);
    while(phead<ptail)
    {
        while(data[index[ptail]]>=pivot && ptail>phead){ptail--;}
        while(data[index[phead]]<=pivot && phead<ptail){phead++;}
        swap=index[phead];index[phead]=index[ptail];index[ptail]=swap;
    }
    return phead;
}

int arcQuickSort(int head, int tail, int* index, int* data) {
    int pivot;
    if(tail<8+head){
	    arcSimSort(head,tail,index,data);
	    return 0;
    }
    pivot=arcPivotSort(head, tail, index, data);
    arcQuickSort(head, pivot, index, data);
    arcQuickSort(pivot+1, tail, index, data);
}

int version_print(char *pName){
    fprintf(stdout,"%s --1.0.1\nearly version\n",pName);
    return 0;
}

int usage_print(char *pName){
    version_print(pName);
    fprintf(stdout,"example usage: %s serverlist.txt --thread 4\n",pName);
    fprintf(stdout,"example usage: %s serverlist.txt --verbose 2>srvip_malf\n",pName);
    fprintf(stdout,"\nshow this page\n  --help or -h\n");
    fprintf(stdout,"\nshow version only:\n  --version or -v\n");
    fprintf(stdout,"\nuse html page to display:\n  --web servers.html\n");
    fprintf(stdout,"\nturn on error log: (output as stderr)\n  --log-on or -l\n");
    fprintf(stdout,"\nshow even more detail when querying: (verbose mode)\n --verbose or -V\n");
    fprintf(stdout,"\ndefine your own HTML header and footer:\n  --header xxx.html --footer yyy.html\n");
    fprintf(stdout,"\n\ntips: default thread number is 6, value larger than 16 may cause some problems.\n");
    return 0;
}


/*
*   end of define part
*/

/*   =======================================    */

int main(int argc, char * argv[])
{
    
    struct option long_option[]=
    {
		{"help", 0, NULL, 'h'},
        {"version", 0, NULL, 'v'},
		{"verbose", 0, NULL, 'V'},
		{"thread", 1, NULL, 't'},
		{"web", 1, NULL, 'w'},
		{"log-on", 0, NULL, 'l'},
        {"footer", 1, NULL, 'F'},
        {"header", 1, NULL, 'H'},
		{"NULL", 0, NULL, 0}
	};

    FILE *srvFile, *htmlFile, *statusFile, *headerFile, *footerFile;
    char srvPath[128], htmlPath[128], statusPath[128], headerPath[128], footerPath[128];
    struct valveServList mylist;
    int myrule[MAXSERVER]={0};
    int Copt,pf,pv,openslots,players;

/*Initate some default setting*/
    masterGlobalVar.opt_verbose=0;
    masterGlobalVar.opt_thread=6;
    masterGlobalVar.opt_web=0;
    masterGlobalVar.opt_footer=0;
    masterGlobalVar.opt_header=0;
    masterGlobalVar.opt_logon=0;

    while(!((Copt = getopt_long(argc, argv, "hvVlt:w:F:H:", long_option, NULL)) < 0)) {
        switch(Copt){
	        case 'h':
		        usage_print(argv[0]);
		        return 0;
            case 'v':
                version_print(argv[0]);
                return 0;
            case 'V':
                masterGlobalVar.opt_verbose=1;
                masterGlobalVar.opt_logon=1;
                break;
            case 't':
                masterGlobalVar.opt_thread = atoi(optarg);
                masterGlobalVar.opt_thread<1?1:masterGlobalVar.opt_thread;
                masterGlobalVar.opt_thread>16?16:masterGlobalVar.opt_thread;
                break;
            case 'w':
                masterGlobalVar.opt_web=1; pf=0;
		        while(optarg[pf]!=0){htmlPath[pf]=optarg[pf];pf++;}
                htmlPath[pf]=0; pf=0;
                break;
            case 'l':
            case 'L':
                masterGlobalVar.opt_logon=1;
                break;
            case 'H':
                masterGlobalVar.opt_header=1; pf=0;
                while(optarg[pf]!=0){headerPath[pf]=optarg[pf];pf++;}
                headerPath[pf]=0; pf=0;
                break;
            case 'F':
                masterGlobalVar.opt_footer=1; pf=0;
                while(optarg[pf]!=0){footerPath[pf]=optarg[pf];pf++;}
                footerPath[pf]=0; pf=0;
                break;
        }
    }
    if(optind==argc) {
        fprintf(stdout,"\033[33m using default list ~/.serverlist\033[0m\n\n");
        sprintf(srvPath,"%s/.serverlist",getenv("HOME"));
    }else{
        pf=0;   /* Copy the input path to srvPath[] */
        while(argv[optind][pf]!=0){srvPath[pf]=argv[optind][pf];pf++;}
        srvPath[pf]=0;pf=0;
    }

    if((srvFile=fopen(srvPath,"r"))==NULL) {
        fprintf(stderr,"critical: \033[31mcan not read %s\033[0m\n", srvPath);
        return -1;
    }
    fscanIp2srvList(srvFile, &mylist);
    fclose(srvFile);
/*
*   Decide which scheme to use, no query is performed at this stage.
*/
    if(masterGlobalVar.opt_verbose){
        fprintf(stdout,"Querying...\n");
    }
    queryList_mt(&mylist, masterGlobalVar.opt_thread);


/*
*   Make your own rule designed for sort, a map to int
*/
    for(pf=0;pf<mylist.length;pf++){
        players=mylist.server[pf].players;
        openslots=mylist.server[pf].slots-players; openslots=openslots>0?openslots:0; openslots=openslots<10?openslots:10;
        pv=players>0?(players<4?(700+64*players):(64*openslots+64)):0;
        pv=openslots>0?pv:64;
        /*your own rule designed for sort*/
        myrule[pf]=pf+pv+999*mylist.server[pf].status;
    }

/*
*   Sort the index of serverlist by your rule,
*   the small value will be placed at first.
*/
    if(masterGlobalVar.opt_verbose){
        fprintf(stdout,"Sorting...\n");
    }
    arcQuickSort(0,mylist.length-1,mylist.index,myrule);

/*
*   Output depend on the globalVar option
*/
    if(masterGlobalVar.opt_web){

        if((htmlFile=fopen(htmlPath,"w"))==NULL){
            fprintf(stderr,"can not write %s\n",htmlPath);
            return -1;
        }

        if(masterGlobalVar.opt_header){
            if((headerFile=fopen(headerPath,"r"))==NULL){
                fprintf(stderr,"can not read %s\n",headerPath);
                return -1;
            }
            fprintfHTML_DIY(htmlFile, headerFile);
            fclose(headerFile);
        }else{
            fprintHTML_header_default(htmlFile);
        }

        fprintHTML_content(htmlFile, &mylist);

        if(masterGlobalVar.opt_footer){
            if((footerFile=fopen(footerPath,"r"))==NULL){
                fprintf(stderr,"can not read %s\n",footerPath);
                return -1;
            }
            fprintfHTML_DIY(htmlFile, footerFile);
            fclose(footerFile);
        }else{
            fprintHTML_footer_default(htmlFile);
        }

        fclose(htmlFile);

        if(settleJsPath(statusPath,htmlPath)){
            fprintf(stderr,"fail to settle js path\n");
            return -1;
        }
        if((statusFile=fopen(statusPath,"w"))==NULL){
            fprintf(stderr,"can not write %s\n",statusPath);
            return -1;
        }
        updateStatusJS(statusFile, &mylist);
        fclose(statusFile);
    }else{
        fprint_console(&mylist);
    }

    pthread_mutex_destroy(&mutex);

    return 0;
}
