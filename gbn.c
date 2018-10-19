#define _XOPEN_SOURCE

#include "gbn.h"

state_t state;
/*--- Timeout ---*/
volatile sig_atomic_t timeoutFlag = 0;

/*the timeoutHandler for signal()*/
static void timeoutHandler(int sig) {
    timeoutFlag = 1;
    state.window_size = 1;
    printf("    timeout!!!\n");
    return;
}

/*timeout resetter*/
void timeoutReset() {
    timeoutFlag = 0;
}

gbnhdr* generatePacket(int type, uint8_t sequence_num, char *buffer, int data_length)
{
    gbnhdr * packet = malloc(sizeof(gbnhdr));
    packet->type = type;
    packet->seqnum = sequence_num;
    memcpy(packet->data, buffer, data_length);
    packet->payloadLen = data_length;
    /*packet->checksum = (uint16_t) packet_checksum(packet);*/
    return packet;
}

gbnhdr* generateEmptyPacket(int type, uint8_t sequence_num)
{
    gbnhdr * packet = malloc(sizeof(gbnhdr));
    packet->type = type;
    packet->seqnum = sequence_num;
    packet->checksum = (uint16_t)0;
    return packet;
}

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t packet_checksum(gbnhdr *hdr){
    int bufLen = sizeof(uint8_t) * 2 + sizeof(uint16_t) + sizeof(int) + sizeof(hdr->data);
    uint16_t *buffer = malloc (sizeof(uint16_t) * bufLen);
    buffer[0] = (uint16_t)hdr->seqnum;
    buffer[1] = (uint16_t)hdr->type;
    buffer[2] = (uint16_t)hdr->payloadLen;
    memcpy(buffer + 3, hdr->data, sizeof(hdr->data));
    return checksum(buffer, (bufLen / sizeof(uint16_t)));
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
    
    gbnhdr *dataPacket = malloc(sizeof(*dataPacket));
    gbnhdr *dataAck = malloc(sizeof(*dataAck));
    struct sockaddr from;
    socklen_t fromLen = sizeof(from);
    
    int i = 0; /*bytes that already sent*/
    int j = 0; /*rounds of sending*/
    int attempts = 0;
    int unACKed;
    int retran = 0;
    while(i < len) {
        unACKed = 0;
        switch (state.type) {
            case ESTABLISHED:
                attempts = 0;
                for (j = 0; j < state.window_size; j++) {
                    if (len > (i + (DATALEN) * j)){
                        size_t data_length;
                        if(len - i - DATALEN * j < DATALEN){
                            data_length=len - i - DATALEN * j;
                        }
                        else{
                            data_length=DATALEN;
                        }
                        dataPacket = generateEmptyPacket(DATA, state.seqnum + (uint8_t) j);
                        memset(dataPacket->data, '0x0', DATALEN);
                        memcpy(dataPacket->data, buf + i + (DATALEN) * j, data_length);
                        dataPacket->payloadLen = data_length;
                        dataPacket->checksum = packet_checksum(dataPacket);
                        if (attempts < 5) {
                            if(sendto(sockfd, dataPacket, sizeof(*dataPacket), 0, state.sock_address, sizeof(*state.sock_address))==-1){
                                printf("    send failed\n");
                                state.type = CLOSED;
                                break;
                            }
                            /*printf("    data already sent, seqnum %d\n", dataPacket->seqnum);*/
                        } else {
                            printf("Error in sending, resetting state to CLOSED.\n");
                            state.type = CLOSED;
                            return -1;
                        }
                        unACKed++;
                    }
                }
                attempts++;
                size_t ACKed = 0;
                /*printf("    unACKed: %d\n", unACKed);*/
                for (j = 0; j < unACKed && state.type != FIN_RCVD; ) {
                    int temp;
                    while (1){

                        struct sigaction alarmact;
                        bzero(&alarmact,sizeof(alarmact));
                        alarmact.sa_handler = timeoutHandler;
                        alarmact.sa_flags = SA_NOMASK;
                        sigaction(SIGALRM,&alarmact,NULL);

                        timeoutReset();
                        temp = 0;
                        alarm(TIMEOUT);
                        temp = maybe_recvfrom(sockfd, dataAck, sizeof(*dataAck), 0, &from, &fromLen);
                        if(temp >= 0 && timeoutFlag != 1){
                            alarm(0);
                            if (dataAck->type == DATAACK && dataAck->checksum == packet_checksum(dataAck)) {
                                int diff = ((int)dataAck->seqnum - (int)state.seqnum);
                                if(diff >= 0){
                                    ACKed = (size_t)(diff);
                                } else {
                                    ACKed = (size_t)(diff + 256);
                                    diff += 256;
                                }

                                printf("    dataACK received and ask for %d.\n",dataAck->seqnum);


                                unACKed -= ACKed;

                                state.seqnum = dataAck->seqnum;

                                
                                if (state.window_size <= 2 && unACKed == 0) {
                                    state.window_size = 2 * state.window_size;
                                    /*printf("    window size rise to: %d.\n", state.window_size);*/
                                }
                                if(diff != 0){
                                    int jj;
                                    for (jj = 0; jj < diff; jj++) {
                                        if(len - i < DATALEN){
                                            i += len - i;
                                        }
                                        else{
                                            i+=DATALEN;
                                        }
                                    }
                                    break;
                                }else{
                                    
                                }
                            } else if (dataAck->type == FIN && dataAck->checksum == packet_checksum(dataAck)) {
                                attempts = 0;
                                state.type = FIN_RCVD;
                                state.isEnd = 1;
                                break;
                            }
                            
                        } else if(timeoutFlag == 1){
                            /*printf("window: %d\n", state.window_size);*/
                            unACKed = 0;
                            printf("Sending ... \n");
                            break;
                        }
                        if(temp < 0){
                            if (errno == EINTR) {
                                break;
                            } else {
                                state.type = CLOSED;
                                return -1;
                            }
                        }
                    }
                }
                break;
                
            case CLOSED:
                gbn_close(sockfd);
                break;
                
            case SYN_RCVD:
                gbn_close(sockfd);
                break;
                
            default: break;
        }
    }
    free(dataPacket);
    free(dataAck);
    return len;
    
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

    gbnhdr *dataPacket = malloc(sizeof(*dataPacket));
    gbnhdr *dataAck = malloc(sizeof(*dataAck));
    struct sockaddr from;
    socklen_t fromLen = sizeof(from);
    int numRead = 0;
    while (state.type == ESTABLISHED && numRead == 0) {
        gbnhdr *dataPacket = malloc(sizeof(*dataPacket));
        memset(dataPacket,'\0',sizeof(*dataPacket));
        if (maybe_recvfrom(sockfd,dataPacket, sizeof(*dataPacket), 0, &from, &fromLen) > 0 ) {
            /*if(dataPacket->type > 127) dataPacket->type -= 128;*/
            

            if (dataPacket->type == DATA && dataPacket->checksum == packet_checksum(dataPacket)) {
                if (dataPacket->seqnum == state.seqnum ) {
                    /*printf("    dataPacket %d received\n", dataPacket->seqnum);*/
                    state.seqnum = dataPacket->seqnum + (uint8_t) 1;
                    memset(buf,'\0',DATALEN);
                    memcpy(buf, dataPacket->data, sizeof(dataPacket->data));
                    numRead = dataPacket->payloadLen;
                } else {
                    /*printf("Not match: state seq %d, dataPacket seq %d \n", state.seqnum, dataPacket->seqnum);*/
                    printf("Recving ... \n");
                }
                dataAck = generateEmptyPacket(DATAACK, state.seqnum);
                dataAck->checksum = packet_checksum(dataAck);
                if (sendto(sockfd, dataAck, sizeof(*dataAck), 0, state.sock_address, sizeof(*state.sock_address)) == -1) {
                    printf("    Error in sending data acknowledgment. %d \n", errno);
                    state.type = CLOSED;
                } else {
                    /*printf("    dataACK sent and ask for %d.\n", dataAck->seqnum);*/
                }
            }else if (dataPacket->type == FIN && dataPacket->checksum == packet_checksum(dataPacket)) {
                state.seqnum = dataPacket->seqnum + (uint8_t) 1;
                state.type = FIN_RCVD;
            }else if ((dataPacket->type == SYN || dataPacket->type - 128 == SYN) && dataPacket->checksum == packet_checksum(dataPacket)){
                gbnhdr *SYNACK_packet = generateEmptyPacket(SYNACK, 0);
                SYNACK_packet->checksum = packet_checksum(SYNACK_packet);
                sendto(sockfd, SYNACK_packet, sizeof(*SYNACK_packet), 0, &from, sizeof(*state.sock_address));
                state.type = ESTABLISHED;
                state.sock_address = &from;
                printf("    accept success!\n");
            } else if(dataPacket->type == 0 && dataPacket->checksum != packet_checksum(dataPacket)){
                if (maybe_recvfrom(sockfd,dataPacket, sizeof(*dataPacket), 0, &from, &fromLen) > 0 ) {

                }
                dataAck = generateEmptyPacket(DATAACK, state.seqnum);
                dataAck->checksum = packet_checksum(dataAck);
                if (sendto(sockfd, dataAck, sizeof(*dataAck), 0, state.sock_address, sizeof(*state.sock_address)) == -1) {
                    printf("    Error in sending data acknowledgment. %d \n", errno);
                    state.type = CLOSED;
                } else {
                    /*printf("    dataACK sent and ask for %d.\n", dataAck->seqnum);*/
                }
            }
        } else {
            if (errno != EINTR) {
                state.type = CLOSED;
                return -1;
            }
        }
    }
    free(dataPacket);
    free(dataAck);
    if(state.type == CLOSED){
        return -1;
    }
    return numRead;
}

int gbn_close(int sockfd){
    /* TODO: Your code here. */
    gbnhdr *fin1 = malloc(sizeof(*fin1));
    gbnhdr *fin2 = malloc(sizeof(*fin2));
    gbnhdr *finAck1 = malloc(sizeof(*finAck1));
    gbnhdr *finAck2 = malloc(sizeof(*finAck2));
    struct sockaddr from;
    socklen_t fromlen = sizeof(from);
    socklen_t socklen = sizeof(state.sock_address);
    int attempts = 0;
    while (state.type != CLOSED) {
        switch (state.type) {
            case ESTABLISHED:
                fin2 = generateEmptyPacket(FIN, state.seqnum);
                fin2->checksum = packet_checksum(fin2);
                if (attempts < 5) {
                    int res = sendto(sockfd, fin2, sizeof(*fin2), 0, state.sock_address, sizeof(*state.sock_address));
                    if (res == -1) {
                        printf("Error sending FIN2.\n");
                        state.type = CLOSED;
                        return -1;
                    }
                    printf("FIN2 sent.\n");
                    attempts++;
                    
                } else {
                    printf("Error in FIN2, resetting state to CLOSED.\n");
                    state.type = CLOSED;
                    return -1;
                }

                struct sigaction alarmact;
                bzero(&alarmact,sizeof(alarmact));
                alarmact.sa_handler = timeoutHandler;
                alarmact.sa_flags = SA_NOMASK;
                sigaction(SIGALRM,&alarmact,NULL);

                alarm(TIMEOUT);
                timeoutReset();

                if (maybe_recvfrom(sockfd, finAck2, sizeof(*finAck2), 0, &from, &fromlen) >= 0 && timeoutFlag == 0) {
                    alarm(0);
                    if ((finAck2->type == FINACK || finAck2->type == FIN) && finAck2->checksum == packet_checksum(finAck2)) {
                        printf("FINACK2 received.\n");
                        if(finAck1->type == FINACK && finAck1->checksum == packet_checksum(finAck1)){
                            state.type = CLOSED;
                            break;
                        } else {
                            printf("Waiting for FIN.\n");
                            state.type = FIN_SENT;
                            break;
                        }
                    }
                } else {
                    if(errno != EINTR) {
                        printf("Error receiving FINACK2");
                        state.type = CLOSED;
                    }
                }
                break;
            case FIN_SENT:
                if (maybe_recvfrom(sockfd, fin1, sizeof(*fin1), 0, &from, &fromlen) >= 0) {
                    if (fin1->type == FIN && fin1->checksum == packet_checksum(fin1)) {
                        printf("FIN1 received.\n");
                        state.seqnum = fin1->seqnum + (uint8_t) 1;
                        state.type = FIN_RCVD;
                    }
                } else {
                    if (errno != EINTR) {
                        printf("Error receiving FIN1.\n");
                        state.type = CLOSED;
                        break;
                    }
                }
                break;
            case FIN_RCVD:
                finAck1 = generateEmptyPacket(FINACK, state.seqnum);
                finAck1->checksum = packet_checksum(finAck1);
                if (sendto(sockfd, finAck1, sizeof(*finAck1), 0, state.sock_address, sizeof(*state.sock_address)) >=0) {
                    printf("FINACK1 sent.\n");
                    /*alarm(0);*/
                    if (finAck2->type == FINACK && finAck2->checksum == packet_checksum(finAck2)) {
                        state.type = CLOSED;
                    } else {
                        state.type = ESTABLISHED;
                    }
                } else {
                    printf("Error sending FINACK1.\n");
                    state.type = CLOSED;
                    break;
                }
                break;
            default: break;
        }
    }
    free(fin1);
    free(fin2);
    free(finAck1);
    free(finAck2);
    if (state.type == CLOSED){
        printf("CLOSED.\n");
        return close(sockfd);
    }
    return -1;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
	/* TODO: Your code here. */
    
    state.type = SYN_SENT;
    
    /*fill needed fields in packet*/
    gbnhdr *SYN_packet = generateEmptyPacket(SYN, state.seqnum);
    
    /*prepare for response*/
    gbnhdr *response = malloc(sizeof(*response));
    struct sockaddr socket_ack;
    socklen_t ack_len = sizeof(socket_ack);
    
    int count = 0;
    while(state.type != ESTABLISHED && count < 5){
        count++;
        /*send out the connection request*/
        SYN_packet->checksum = packet_checksum(SYN_packet);
        if(sendto(sockfd, &SYN_packet, sizeof(SYN_packet), 0, server, socklen)==-1){
            printf("    send SYN failed\n");
            state.type = CLOSED;
            return -1;
        }
        state.type = SYN_SENT;

        struct sigaction alarmact;
        bzero(&alarmact,sizeof(alarmact));
        alarmact.sa_handler = timeoutHandler;
        alarmact.sa_flags = SA_NOMASK;
        sigaction(SIGALRM,&alarmact,NULL);

        alarm(TIMEOUT);
        timeoutReset();
        if(recvfrom(sockfd, response, sizeof(*response), 0, &socket_ack, &ack_len) == -1 || timeoutFlag == 1 || response->type != SYNACK){
            printf("    recv SYNACK fail\n");
            continue;
        }
        alarm(0);
        state.type = ESTABLISHED;
        state.seqnum = response->seqnum;
        state.sock_address = server;
        printf("    connection success!\n");
    }
    
    if(count >= 5) printf("    connection failed\n");
}

int gbn_listen(int sockfd, int backlog){
	/* TODO: Your code here. */
	return(0);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	/* TODO: Your code here. */
    return bind(sockfd, server, sizeof(*server));
}


int gbn_socket(int domain, int type, int protocol){
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	/* TODO: Your code here. */
    state.seqnum = 0;
    state.window_size = 1;
    return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
	/* TODO: Your code here. */
    gbnhdr *buf = malloc(sizeof(gbnhdr));
    while(state.type != ESTABLISHED){
        if(maybe_recvfrom(sockfd, buf, sizeof(*buf), 0, client, socklen) == -1) return -1;
        if(buf->type == SYN || buf->type - 128 == SYN){
            /*fill needed fields in packet*/
            gbnhdr *SYNACK_packet = generateEmptyPacket(SYNACK, 0);
            SYNACK_packet->checksum = packet_checksum(SYNACK_packet);
            sendto(sockfd, SYNACK_packet, sizeof(*SYNACK_packet), 0, client, *socklen);
            state.type = ESTABLISHED;
            state.sock_address = client;
            printf("    accept success!\n");
        }
    }
    return sockfd;
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){

        /*----- Receiving the packet -----*/
        int retval = recvfrom(s, buf, len, flags, from, fromlen);

        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buf[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buf[index] = c;
        }

        return retval;
    }
    /*----- Packet lost -----*/
    return(len);  /* Simulate a success */
	
}
