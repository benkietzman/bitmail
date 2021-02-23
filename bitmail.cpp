// vim600: fdm=marker
/* -*- c++ -*- */
///////////////////////////////////////////
// BitMail
// -------------------------------------
// file       : bitmail.cpp
// author     : Ben Kietzman
// begin      : 2013-08-19
// copyright  : kietzman.org
// email      : ben@kietzman.org
///////////////////////////////////////////

/**************************************************************************
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
**************************************************************************/

/*! \file bitmail.cpp
* \brief BitMail Daemon
*
* Provides IMAP/POP/SMTP access to BitMessage.
*/
// {{{ includes
#include <cerrno>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>
using namespace std;
#include <BitMessage>
#include <Json>
#include <Utility>
#include <StringManip>
using namespace common;
// }}}
// {{{ defines
#ifdef VERSION
#undef VERSION
#endif
/*! \def VERSION
* \brief Contains the application version number.
*/
#define VERSION "0.1"
/*! \def mUSAGE(A)
* \brief Prints the usage statement.
*/
#define mUSAGE(A) cout << endl << "Usage:  "<< A << " [options]"  << endl << endl << " -d, --daemon" << endl << "     Turns the process into a daemon." << endl << endl << " -c, --conf" << endl << "     Sets the configuration directory." << endl << endl << " -h, --help" << endl << "     Displays this usage screen." << endl << endl << " -v, --version" << endl << "     Displays the current version of this software." << endl << endl
/*! \def mVER_USAGE(A,B)
* \brief Prints the version number.
*/
#define mVER_USAGE(A,B) cout << endl << A << " Version: " << B << endl << endl
/*! \def BITMAIL_CONFIG
* \brief Contains the BitMail configuration path.
*/
#define BITMAIL_CONFIG "/bitmail.conf"
/*! \def CERTIFICATE
* \brief Contains the certificate path.
*/
#define CERTIFICATE "/bitmail.crt"
/*! \def PRIVATE_KEY
* \brief Contains the key path.
*/
#define PRIVATE_KEY "/bitmail.key"
// }}}
// {{{ structs
struct account
{
  bool bImap;
  bool bPop;
  bool bSmtp;
  map<string, string> imap;
  map<string, string> pop;
  map<string, string> smtp;
  BitMessage bitMessage;
};
// }}}
// {{{ global variables
static bool gbDaemon = false; //!< Global daemon variable.
static map<string, account *> gConf; //!< Global configuration.
static string gstrConf = "/etc/bitmail"; //!< Global data path.
static BitMessage gBitMessage; //!< Global BitMessage class.
// }}}
// {{{ prototypes
/*! \fn bool authenticate(const string strProtocol, const string strUser, const string strPassword, string &strAccount)
* \brief Authenticate a session.
* \param strProtocol Contains the protocol.
* \param strUser Contains the user.
* \param strPassword Contains the password.
* \return Returns the account.
*/
bool authenticate(const string strProtocol, const string strUser, const string strPassword, string &strAccount);
/*! \fn string buildHeaders(map<string, string> message, string &strHeaders)
* \brief Build email headers for BitMessage.
* \param message Contains the BitMessage.
* \param strHeaders Contains the resultant email headers.
* \return Returns the resultant email headers.
*/
string buildHeaders(map<string, string> message, string &strHeaders);
/*! \fn void formatTime(const string strTimeStamp, string &strFormatted)
* \brief Format date/time from BitMessage to email.
* \param strTimeStamp Contains the Unix timestamp.
* \param strFormatted Contains the resultant formatted date/time.
*/
void formatTime(const string strTimeStamp, string &strFormatted);
/*! \fn void imap(SSL *ssl)
* \brief Processes a IMAP connection.
* \param ssl Contains the SSL handle.
*/
void imap(SSL *ssl);
/*! \fn bool readLine(SSL *ssl, string &strBuffer, const string strPrefix, string &strLine)
* \brief Reads a line of data.
* \param ssl Contains the input SSL handle.
* \param strBuffer Contains the buffer.
* \param strPrefix Contains the cout prefix.
* \param strLine Contains the resultant line of data.
* \return Returns a boolean true/false value.
*/
bool readLine(SSL *ssl, string &strBuffer, const string strPrefix, string &strLine);
/*! \fn void pop(SSL *ssl)
* \brief Processes a POP connection.
* \param ssl Contains the SSL handle.
*/
void pop(SSL *ssl);
/*! \fn void smtp(SSL *ssl)
* \brief Processes a SMTP connection.
* \param ssl Contains the SSL handle.
*/
void smtp(SSL *ssl);
/*! \fn bool writeLine(SSL *ssl, const string strPrefix, string strLine)
* \brief Writes a line of data.
* \param ssl Contains the output SSL handle.
* \param strPrefix Contains the cout prefix.
* \param strLine Contains the line of data to be written.
* \return Returns a boolean true/false value.
*/
bool writeLine(SSL *ssl, const string strPrefix, string strLine);
// }}}
// {{{ main()
/*! \fn int main(int argc, char *argv[])
* \brief This is the main function.
* \return Exits with a return code for the operating system.
*/
int main(int argc, char *argv[])
{
  ifstream inConf;
  map<string, int> imapPort, popPort, smtpPort;
  SSL_METHOD *method = (SSL_METHOD *)SSLv23_server_method();
  SSL_CTX *ctx;
  string strError;
  StringManip manip;
  Utility utility(strError);

  // {{{ command line arguments
  for (int i = 1; i < argc; i++)
  {
    string strArg = argv[i];
    if (strArg == "-d" || strArg == "--daemon")
    {
      gbDaemon = true;
    }
    else if (strArg.size() > 7 && strArg.substr(0, 7) == "--conf=")
    {
      if (strArg == "-c" && i + 1 < argc && argv[i+1][0] != '-')
      {
        gstrConf = argv[++i];
      }
      else
      {
        gstrConf = strArg.substr(7, strArg.size() - 7);
      }
      manip.purgeChar(gstrConf, gstrConf, "'");
      manip.purgeChar(gstrConf, gstrConf, "\"");
    }
    else if (strArg == "-h" || strArg == "--help")
    {
      mUSAGE(argv[0]);
      return 0;
    }
    else if (strArg == "-v" || strArg == "--version")
    {
      mVER_USAGE(argv[0], VERSION);
      return 0;
    }
    else
    {
      cout << endl << "Illegal option, '" << strArg << "'." << endl;
      mUSAGE(argv[0]);
      return 0;
    }
  }
  // }}}
  // {{{ parse configuration file
  inConf.open((gstrConf + (string)BITMAIL_CONFIG).c_str());
  if (inConf)
  {
    string strConf;
    while (utility.getLine(inConf, strConf))
    {
      map<string, string> conf;
      Json tJson(strConf);
      tJson.flatten(conf, true);
      if (conf.find("BitMessage Identity") != conf.end() && conf.find("BitMessage User") != conf.end() && conf.find("BitMessage Password") != conf.end())
      {
        account *ptAccount = new account;
        if (conf.find("BitMessage Server") == conf.end())
        {
          conf["BitMessage Server"] = "localhost";
        }
        if (conf.find("BitMessage Port") == conf.end())
        {
          conf["BitMessage Port"] = "8442";
        }
        ptAccount->bImap = false;
        ptAccount->bPop = false;
        ptAccount->bSmtp = false;
        ptAccount->bitMessage.setCredentials(conf["BitMessage User"], conf["BitMessage Password"], conf["BitMessage Server"], conf["BitMessage Port"]);
        if (gConf.find(conf["BitMessage Identity"]) != gConf.end())
        {
          gConf[conf["BitMessage Identity"]]->imap.clear();
          gConf[conf["BitMessage Identity"]]->pop.clear();
          gConf[conf["BitMessage Identity"]]->smtp.clear();
          delete gConf[conf["BitMessage Identity"]];
        }
        gConf[conf["BitMessage Identity"]] = ptAccount;
        if (conf.find("IMAP User") != conf.end() && conf.find("IMAP Password") != conf.end())
        {
          if (conf.find("IMAP Port") == conf.end())
          {
            conf["IMAP Port"] = "993";
          }
          gConf[conf["BitMessage Identity"]]->bImap = true;
          gConf[conf["BitMessage Identity"]]->imap["User"] = conf["IMAP User"];
          gConf[conf["BitMessage Identity"]]->imap["Password"] = conf["IMAP Password"];
          gConf[conf["BitMessage Identity"]]->imap["Port"] = conf["IMAP Port"];
          imapPort[conf["IMAP Port"]] = 0;
        }
        if (conf.find("POP User") != conf.end() && conf.find("POP Password") != conf.end())
        {
          if (conf.find("POP Port") == conf.end())
          {
            conf["POP Port"] = "993";
          }
          gConf[conf["BitMessage Identity"]]->bPop = true;
          gConf[conf["BitMessage Identity"]]->pop["User"] = conf["POP User"];
          gConf[conf["BitMessage Identity"]]->pop["Password"] = conf["POP Password"];
          gConf[conf["BitMessage Identity"]]->pop["Port"] = conf["POP Port"];
          popPort[conf["POP Port"]] = 0;
        }
        if (conf.find("SMTP User") != conf.end() && conf.find("SMTP Password") != conf.end())
        {
          if (conf.find("SMTP Port") == conf.end())
          {
            conf["SMTP Port"] = "465";
          }
          gConf[conf["BitMessage Identity"]]->bSmtp = true;
          gConf[conf["BitMessage Identity"]]->smtp["User"] = conf["SMTP User"];
          gConf[conf["BitMessage Identity"]]->smtp["Password"] = conf["SMTP Password"];
          gConf[conf["BitMessage Identity"]]->smtp["Port"] = conf["SMTP Port"];
          smtpPort[conf["SMTP Port"]] = 0;
        }
      }
    }
  }
  inConf.close();
  // }}}
  if (!gConf.empty())
  {
    if (gbDaemon)
    {
      utility.daemonize();
    }
    setlocale(LC_ALL, "");
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    if ((ctx = SSL_CTX_new(method)) != NULL && SSL_CTX_use_certificate_file(ctx, (gstrConf + CERTIFICATE).c_str(), SSL_FILETYPE_PEM) > 0 && SSL_CTX_use_PrivateKey_file(ctx, (gstrConf + PRIVATE_KEY).c_str(), SSL_FILETYPE_PEM) > 0)
    {
      if (SSL_CTX_check_private_key(ctx))
      {
        bool bListening = true;
        int nReturn;
        map<string, map<string, int> > port;
        struct addrinfo hints;
        struct addrinfo *result;
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        port["IMAP"] = imapPort;
        port["POP"] = popPort;
        port["SMTP"] = smtpPort;
        for (map<string, map<string, int> >::iterator i = port.begin(); i != port.end(); i++)
        {
          for (map<string, int>::iterator j = i->second.begin(); j != i->second.end(); j++)
          {
            if ((nReturn = getaddrinfo(NULL, j->first.c_str(), &hints, &result)) == 0)
            {
              struct addrinfo *rp;
              j->second = 1;
              for (rp = result; j->second < 2 && rp != NULL; rp = rp->ai_next)
              {
                int fdSocket;
                if ((fdSocket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) >= 0)
                {
                  int nOn = 1;
                  setsockopt(fdSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&nOn, sizeof(nOn));
                  if (bind(fdSocket, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fdSocket, 5) == 0)
                  {
                    j->second = fdSocket;
                  }
                  else
                  {
                    close(fdSocket);
                  }
                }
              }
              freeaddrinfo(result);
            }
          }
        }
        for (map<string, map<string, int> >::iterator i = port.begin(); bListening && i != port.end(); i++)
        {
          for (map<string, int>::iterator j = i->second.begin(); bListening && j != i->second.end(); j++)
          {
            if (j->second < 2)
            {
              bListening = false;
            }
          }
        }
        if (bListening)
        {
          bool bExit = false;
          fd_set readfds;
          int nfds;
          socklen_t clilen;
          sockaddr_in cli_addr;
          clilen = sizeof(cli_addr);
          while (!bExit)
          {
            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            nfds = 0;
            FD_ZERO(&readfds);
            for (map<string, map<string, int> >::iterator i = port.begin(); i != port.end(); i++)
            {
              for (map<string, int>::iterator j = i->second.begin(); j != i->second.end(); j++)
              {
                FD_SET(j->second, &readfds);
                nfds = max(nfds, j->second);
              }
            }
            if ((nReturn = select(nfds + 1, &readfds, NULL, NULL, &tv)) > 0)
            {
              for (map<string, map<string, int> >::iterator i = port.begin(); i != port.end(); i++)
              {
                for (map<string, int>::iterator j = i->second.begin(); j != i->second.end(); j++)
                {
                  if (FD_ISSET(j->second, &readfds))
                  {
                    int fdData;
                    if ((fdData = accept(j->second, (struct sockaddr *)&cli_addr, &clilen)) >= 0)
                    {
                      SSL *ssl = SSL_new(ctx);
                      SSL_set_fd(ssl, fdData);
                      if (SSL_accept(ssl) != -1)
                      {
                        if (i->first == "IMAP")
                        {
                          thread tThread(imap, ssl);
                          tThread.detach();
                        }
                        else if (i->first == "POP")
                        {
                          thread tThread(pop, ssl);
                          tThread.detach();
                        }
                        else if (i->first == "SMTP")
                        {
                          thread tThread(smtp, ssl);
                          tThread.detach();
                        }
                      }
                    }
                    else
                    {
                      bExit = true;
                      cerr << i->first << " port " << j->first << " accept error:  " << strerror(errno) << endl;
                    }
                  }
                }
              }
            }
            else if (nReturn < 0 && errno != EINTR)
            {
              bExit = true;
              cerr << "select error:  " << strerror(errno) << endl;
            }
          }
          for (map<string, map<string, int> >::iterator i = port.begin(); i != port.end(); i++)
          {
            for (map<string, int>::iterator j = i->second.begin(); j != i->second.end(); j++)
            {
              close(j->second);
            }
          }
        }
        else
        {
          for (map<string, map<string, int> >::iterator i = port.begin(); i != port.end(); i++)
          {
            for (map<string, int>::iterator j = i->second.begin(); j != i->second.end(); j++)
            {
              if (j->second == 0)
              {
                cerr << i->first << " port " << j->first << " getaddrinfo error:  " << gai_strerror(nReturn) << endl;
              }
              else if (j->second == 1)
              {
                cerr << i->first << " port " << j->first << " socket|bind|listen error:  " << strerror(errno) << endl;
              }
            }
          }
        }
        for (map<string, map<string, int> >::iterator i = port.begin(); i != port.end(); i++)
        {
          i->second.clear();
        }
        port.clear();
      }
      else
      {
        cerr << "Private key does not match the public certificate." << endl;
      }
      SSL_CTX_free(ctx);
    }
    else
    {
      cerr << "Failed to setup SSL context keys." << endl;
    }
    for (map<string, account *>::iterator i = gConf.begin(); i != gConf.end(); i++)
    {
      i->second->imap.clear();
      i->second->pop.clear();
      i->second->smtp.clear();
      delete i->second;
    }
    gConf.clear();
  }
  else
  {
    cerr << "No valid configuration supplied." << endl;
  }
  imapPort.clear();
  popPort.clear();
  smtpPort.clear();

  return 0;
}
// }}}
// {{{ authenticate()
bool authenticate(const string strProtocol, const string strUser, const string strPassword, string &strAccount)
{
  bool bResult = false;

  for (map<string, account *>::iterator i = gConf.begin(); !bResult && i != gConf.end(); i++)
  {
    map<string, string> auth;
    if (strProtocol == "IMAP" && i->second->bImap)
    {
      auth = i->second->imap;
    }
    else if (strProtocol == "POP" && i->second->bPop)
    {
      auth = i->second->pop;
    }
    else if (strProtocol == "SMTP" && i->second->bSmtp)
    {
      auth = i->second->smtp;
    }
    if (!auth.empty())
    {
      cout << strProtocol << " DEBUG:  \"" << auth["User"] << "\" (" << auth["User"].size() << ") " << ((auth["User"] == strUser)?"=":"!") << "= \"" << strUser << "\" (" << strUser.size() << ") && \"" << auth["Password"] << "\" (" << auth["Password"].size() << ") " << ((auth["Password"] == strPassword)?"=":"!") << "= \"" << strPassword << "\" (" << strPassword.size() << ")" << endl;
      if (auth["User"] == strUser && auth["Password"] == strPassword)
      {
        bResult = true;
        strAccount = i->first;
      }
    }
    auth.clear();
  }

  return bResult;
}
// }}}
// {{{ buildHeaders()
string buildHeaders(map<string, string> message, string &strHeaders)
{
  string strDateTime;
  stringstream ssHeader;

  ssHeader << "MIME-Version: 1.0" << endl;
  formatTime(message[((message.find("receivedTime") != message.end())?"receivedTime":"lastActionTime")], strDateTime);
  ssHeader << "Date: " << strDateTime << endl;
  ssHeader << "Subject: " << message["subject"] << endl;
  ssHeader << "From: " << message["fromAddress"] << "@bm.addr" << endl;
  ssHeader << "To: " << ((message["toAddress"] == "Broadcast")?message["fromAddress"]:message["toAddress"]) << "@bm.addr" << endl;
  ssHeader << "Content-Type: text/plain; charset=ISO-8859-1" << endl;
  ssHeader << endl;
  strHeaders = ssHeader.str();

  return strHeaders;
}
// }}}
// {{{ formatTime()
void formatTime(const string strTimeStamp, string &strFormatted)
{
  char szTimeStamp[32] = "\0";
  stringstream ssTimeStamp;
  struct tm tTime;
  time_t CTime;

  ssTimeStamp.str(strTimeStamp);
  ssTimeStamp >> CTime;
  localtime_r(&CTime, &tTime);
  strftime(szTimeStamp, 32, "%a, %d %b %Y %H:%M:%S %z", &tTime);
  strFormatted = szTimeStamp;
}
// }}}
// {{{ imap()
void imap(SSL *ssl)
{
  int fdSocket;
  string strBuffer, strError, strPrefix = "IMAP", strSelectedMailBox;
  stringstream ssPointer;
  StringManip manip;
  Utility utility(strError);

  ssPointer << "[" << ssl << "]";
  strPrefix += ssPointer.str();
  if (writeLine(ssl, strPrefix, "* OK server ready\r\n"))
  {
    bool bAuthenticated = false, bExit = false;
    string strAccount, strLine;
    while (!bExit && readLine(ssl, strBuffer, strPrefix, strLine))
    {
      string strAction, strCommand, strPreCommand, strPreUpperCommand, strUpperCommand;
      stringstream ssBuffer, ssData;
      ssData.str(strLine);
      ssData >> strAction >> strCommand;
      manip.toUpper(strUpperCommand, strCommand);
      if (strUpperCommand == "UID")
      {
        strPreCommand = strCommand;
        strPreUpperCommand = strUpperCommand;
        ssData >> strCommand;
        manip.toUpper(strUpperCommand, strCommand);
      }
      // {{{ CAPABILITY
      if (strUpperCommand == "CAPABILITY")
      {
        ssBuffer << "* " << strCommand << " IMAP4rev1";
        if (!bAuthenticated)
        {
          ssBuffer << " AUTH=LOGIN AUTH=PLAIN";
        }
        ssBuffer << "\r\n";
        ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
      }
      // }}}
      // {{{ AUTHENTICATE
      else if (strUpperCommand == "AUTHENTICATE")
      {
        string strType, strUpperType;
        ssData >> strType;
        manip.toUpper(strUpperType, strType);
        // {{{ LOGIN
        if (strUpperType == "LOGIN")
        {
          string strPrompt, strUser, strPassword;
          gBitMessage.encodeBase64("Username:", strPrompt);
          strPrompt = (string)"+ " + strPrompt + (string)"\r\n";
          writeLine(ssl, strPrefix, strPrompt);
          readLine(ssl, strBuffer, strPrefix, strLine);
          ssData.str(strLine);
          ssData >> strLine;
          gBitMessage.decodeBase64(strLine, strUser);
          gBitMessage.encodeBase64("Password:", strPrompt);
          strPrompt = (string)"+ " + strPrompt + (string)"\r\n";
          writeLine(ssl, strPrefix, strPrompt);
          readLine(ssl, strBuffer, strPrefix, strLine);
          ssData.str(strLine);
          ssData >> strLine;
          gBitMessage.decodeBase64(strLine, strPassword);
          if (authenticate("IMAP", strUser, strPassword, strAccount))
          {
            bAuthenticated = true;
            ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
          }
          else
          {
            ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
          }
        }
        // }}}
        // {{{ PLAIN
        else if (strUpperType == "PLAIN")
        {
          string strAuth;
          writeLine(ssl, strPrefix, "+\r\n");
          readLine(ssl, strBuffer, strPrefix, strLine);
          ssData.str(strLine);
          ssData >> strLine;
          gBitMessage.decodeBase64(strLine, strAuth);
          if (!strAuth.empty() && strAuth[0] == '\0')
          {
            size_t unPosition;
            if ((unPosition = strAuth.find('\0', 1)) != string::npos)
            {
              string strUser = strAuth.substr(1, unPosition - 1), strPassword = strAuth.substr(unPosition + 1, strAuth.size() - (unPosition + 1));
              if (authenticate("IMAP", strUser, strPassword, strAccount))
              {
                bAuthenticated = true;
                ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
              }
              else
              {
                ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
              }
            }
            else
            {
              ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
            }
          }
          else
          {
            ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
          }
        }
        // }}}
        else
        {
          ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
        }
      }
      // }}}
      // {{{ LOGIN
      else if (strUpperCommand == "LOGIN")
      {
        string strPassword, strUser;
        ssData >> strUser >> strPassword;
        if (strUser.size() > 1 && strUser[0] == '"' && strUser[strUser.size() - 1] == '"')
        {
          strUser.erase(0, 1);
          strUser.erase(strUser.size() - 1, 1);
        }
        if (strPassword.size() > 1 && strPassword[0] == '"' && strPassword[strPassword.size() - 1] == '"')
        {
          strPassword.erase(0, 1);
          strPassword.erase(strPassword.size() - 1, 1);
        }
        ssBuffer << strAction << " ";
        if (authenticate("IMAP", strUser, strPassword, strAccount))
        {
          bAuthenticated = true;
          ssBuffer << "OK " << strCommand << " completed";
        }
        else
        {
          ssBuffer << "NO " << strCommand << " failure";
        }
        ssBuffer << "\r\n";
      }
      // }}}
      // {{{ LOGOUT
      else if (strUpperCommand == "LOGOUT")
      {
        bExit = true;
        ssBuffer << "* server logging out\r\n";
        ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
        if (bAuthenticated)
        {
          gConf[strAccount]->bitMessage.trashMessages();
          bAuthenticated = false;
          strAccount.clear();
        }
      }
      // }}}
      // {{{ CHECK or NOOP
      else if (strUpperCommand == "CHECK" || strUpperCommand == "NOOP")
      {
        if (bAuthenticated)
        {
          string strError;
          vector<map<string, string> > message;
          if ((strSelectedMailBox == "INBOX" && gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError)) || (strSelectedMailBox == "SENT" && gConf[strAccount]->bitMessage.getAllSentMessages(strAccount, message, strError)))
          {
            ssBuffer << "* " << message.size() << " EXISTS\r\n";
            ssBuffer << "* 0 RECENT\r\n";
          }
        }
        ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
      }
      // }}}
      else if (bAuthenticated)
      {
        // {{{ LIST
        if (strUpperCommand == "LIST")
        {
          ssBuffer << "* " << strCommand << " (\\HasNoChrildren) \".\" \"INBOX\"\r\n";
          ssBuffer << "* " << strCommand << " (\\HasNoChrildren \\Sent) \".\" \"SENT\"\r\n";
          ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
        }
        // }}}
        // {{{ EXAMINE or SELECT or STATUS
        else if (strUpperCommand == "EXAMINE" || strUpperCommand == "SELECT" || strUpperCommand == "STATUS")
        {
          string strMailBox;
          ssData >> strMailBox;
          if (strMailBox.size() > 1 && strMailBox[0] == '"' && strMailBox[strMailBox.size() - 1] == '"')
          {
            strMailBox.erase(0, 1);
            strMailBox.erase(strMailBox.size() - 1, 1);
          }
          if (strMailBox == "INBOX" || strMailBox == "SENT")
          {
            string strError;
            vector<map<string, string> > message;
            if (strUpperCommand == "EXAMINE" || strUpperCommand == "SELECT")
            {
              strSelectedMailBox = strMailBox;
              if ((strSelectedMailBox == "INBOX" && gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError)) || (strSelectedMailBox == "SENT" && gConf[strAccount]->bitMessage.getAllSentMessages(strAccount, message, strError)))
              {
                ssBuffer << "* FLAGS (\\Deleted \\Seen)\r\n";
                ssBuffer << "* OK [PERMANENTFLAGS ()]\r\n";
                ssBuffer << "* " << message.size() << " EXISTS\r\n";
                ssBuffer << "* 0 RECENT\r\n";
                ssBuffer << "* OK [UNSEEN 0]\r\n";
                ssBuffer << "* OK [UIDNEXT 1]\r\n";
                ssBuffer << strAction << " OK [READ-" << ((strCommand == "EXAMINE")?"ONLY":"WRITE") << "] " << strCommand << " completed\r\n";
              }
              else
              {
                ssBuffer << strAction << " NO " << strCommand << " failure (" << strError << ")\r\n";
              }
            }
            else if ((strMailBox == "INBOX" && gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError)) || (strMailBox == "SENT" && gConf[strAccount]->bitMessage.getAllSentMessages(strAccount, message, strError)))
            {
              ssBuffer << "* " << strCommand << " " << strMailBox << "(UIDNEXT 1 MESSAGES " << message.size() << " UNSEEN 0 RECENT 0)\r\n";
              ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
            }
            else
            {
              ssBuffer << strAction << " NO " << strCommand << " failure (" << strError << ")\r\n";
            }
            for (size_t i = 0; i < message.size(); i++)
            {
              message[i].clear();
            }
            message.clear();
          }
          else
          {
            ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
          }
        }
        // }}}
        // {{{ FETCH
        else if (strUpperCommand == "FETCH")
        {
          list<string> format, deepformat, subformat;
          size_t unPosition;
          string strAssocFormat, strAssocSubFormat, strData, strEnd, strError, strMessages;
          vector<map<string, string> > message;
          ssData >> strMessages;
          // {{{ process formats
          while (ssData >> strData)
          {
            if (strData[0] == '(')
            {
              strData.erase(0, 1);
            }
            if (strData[strData.size() - 1] == ')')
            {
              strData.erase(strData.size() - 1, 1);
            }
            if (!strData.empty())
            {
              string strFormat;
              if ((unPosition = strData.find("[")) != string::npos)
              {
                strAssocFormat = strFormat = strData.substr(0, unPosition);
                strData.erase(0, unPosition + 1);
                if ((unPosition = strData.find("]")) != string::npos)
                {
                  if (unPosition != 0)
                  {
                    subformat.push_back(strData.substr(0, unPosition));
                  }
                }
                else
                {
                  bool bExitSub = false;
                  string strSubFormat;
                  strSubFormat = strData;
                  subformat.push_back(strSubFormat);
                  while (!bExitSub && ssData >> strData)
                  {
                    if (strData[0] == '(')
                    {
                      strAssocSubFormat = strSubFormat;
                      strData.erase(0, 1);
                      if ((unPosition = strData.find(")")) != string::npos)
                      {
                        if (unPosition != 0)
                        {
                          deepformat.push_back(strData.substr(0, unPosition));
                        }
                      }
                      else
                      {
                        bool bExitDeep = false;
                        string strDeepFormat;
                        deepformat.push_back(strData);
                        while (!bExitDeep && ssData >> strData)
                        {
                          if ((unPosition = strData.find(")")) != string::npos)
                          {
                            bExitDeep = true;
                            if (unPosition != 0)
                            {
                              deepformat.push_back(strData.substr(0, unPosition));
                              strData.erase(0, unPosition + 1);
                            }
                          }
                          else
                          {
                            deepformat.push_back(strData);
                          }
                        }
                      }
                    }
                    if ((unPosition = strData.find("]")) != string::npos)
                    {
                      bExitSub = true;
                      if (unPosition != 0)
                      {
                        strSubFormat = strData.substr(0, unPosition);
                        strData.erase(0, unPosition + 1);
                        subformat.push_back(strSubFormat);
                      }
                    }
                    else if (!strData.empty())
                    {
                      strSubFormat = strData;
                      subformat.push_back(strSubFormat);
                    }
                  }
                }
              }
              else
              {
                strFormat = strData;
              }
              format.push_back(strFormat);
            }
          }
          // }}}
          if (!format.empty() && ((strSelectedMailBox == "INBOX" && gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError)) || (strSelectedMailBox == "SENT" && gConf[strAccount]->bitMessage.getAllSentMessages(strAccount, message, strError))))
          {
            string strRange;
            if ((unPosition = strMessages.find(",")) != string::npos)
            {
              strRange = strMessages.substr(0, unPosition);
              strMessages.erase(0, unPosition + 1);
            }
            else
            {
              strRange = strMessages;
              strMessages.clear();
            }
            while (!strRange.empty())
            {
              size_t unEnd, unStart;
              if ((unPosition = strRange.find(":")) != string::npos)
              {
                unStart = atoi(strRange.substr(0, unPosition).c_str());
                if (strRange.substr(unPosition + 1, strRange.size() - (unPosition + 1)) == "*")
                {
                  unEnd = 0;
                }
                else
                {
                  unEnd = atoi(strRange.substr(unPosition + 1, strRange.size() - (unPosition + 1)).c_str());
                }
              }
              else
              {
                unStart = unEnd = atoi(strRange.c_str());
              }
              for (size_t i = (unStart - 1); i < ((unEnd == 0)?message.size():unEnd); i++)
              {
                if (i < message.size())
                {
                  bool bFirst = true, bFoundHeader = false;;
                  list<map<string, string> > param;
                  map<string, string> header;
                  string strBody, strHeader;
                  stringstream ssHeader;
                  strBody = message[i]["message"];
                  if (strBody.find("Content-Type: ") != string::npos)
                  {
                    bool bNewLine = false, bBoth = false;
                    size_t nPosition;
                    if ((nPosition = strBody.find("\n\n")) != string::npos)
                    {
                      bNewLine = true;
                    }
                    else if ((nPosition = strBody.find("\r\n\r\n")) != string::npos)
                    {
                      bBoth = true;
                    }
                    if (bNewLine || bBoth)
                    {
                      bFoundHeader = true;
                      nPosition += (bNewLine)?2:4;
                      strHeader = strBody.substr(0, nPosition);
                      strBody.erase(0, nPosition);
                    }
                  }
                  if (!bFoundHeader)
                  {
                    buildHeaders(message[i], strHeader);
                  }
                  ssHeader.str(strHeader);
                  while (utility.getLine(ssHeader, strLine))
                  {
                    size_t nPosition;
                    if ((nPosition = strLine.find(":")) != string::npos)
                    {
                      string strField, strValue;
                      manip.trim(strField, strLine.substr(0, nPosition));
                      manip.trim(strValue, strLine.substr(nPosition + 1, strLine.size() - (nPosition + 1)));
                      if (strField == "Content-Type" && (nPosition = strValue.find(";")) != string::npos)
                      {
                        bool bEnd;
                        string strParam;
                        manip.trim(strParam, strValue.substr(nPosition + 1, strValue.size() - (nPosition + 1)));
                        strValue.erase(nPosition, strValue.size() - nPosition);
                        if (strParam.empty())
                        {
                          utility.getLine(ssHeader, strParam);
                        }
                        do
                        {
                          string strPair;
                          bEnd = true;
                          manip.trim(strParam, strParam);
                          if (strParam[strParam.size() - 1] == ';')
                          {
                            bEnd = false;
                          }
                          for (int j = 1; !manip.trim(strPair, manip.getToken(strPair, strParam, j, ";", true)).empty(); j++)
                          {
                            map<string, string> pair;
                            string strFirst, strSecond;
                            manip.trim(strFirst, manip.getToken(strFirst, strPair, 1, "=", false));
                            manip.trim(strSecond, manip.getToken(strSecond, strPair, 2, "=", false));
                            pair[strFirst] = strSecond;
                            param.push_back(pair);
                            pair.clear();
                          }
                        } while (!bEnd && utility.getLine(ssHeader, strParam));
                      }
                      header[strField] = strValue;
                    }
                  }
                  ssBuffer << "* " << (i + 1) << " " << strCommand << " (";
                  if (strPreUpperCommand == "UID")
                  {
                    bFirst = false;
                    ssBuffer << strPreCommand << " " << (i + 1);
                  }
                  for (list<string>::iterator j = format.begin(); j != format.end(); j++)
                  {
                    if (((*j) == "BODY" && strAssocFormat == "BODY") || ((*j) == "BODY.PEEK" && strAssocFormat == "BODY.PEEK"))
                    {
                      if (!subformat.empty())
                      {
                        for (list<string>::iterator k = subformat.begin(); k != subformat.end(); k++)
                        {
                          if ((*k) == "HEADER.FIELDS" && strAssocSubFormat == "HEADER.FIELDS")
                          {
                            stringstream ssEmail;
                            ssBuffer << ((!bFirst)?" ":"") << "BODY[" << (*k) << " (";
                            for (list<string>::iterator l = deepformat.begin(); l != deepformat.end(); l++)
                            {
                              if (l != deepformat.begin())
                              {
                                ssBuffer << " ";
                              }
                              ssBuffer << (*l);
                            }
                            ssBuffer << ")] {";
                            for (list<string>::iterator l = deepformat.begin(); l != deepformat.end(); l++)
                            {
                              string strLine, strUpper;
                              manip.toUpper(strUpper, (*l));
                              for (map<string, string>::iterator m = header.begin(); m != header.end(); m++)
                              {
                                string strUpperField;
                                manip.toUpper(strUpperField, m->first);
                                if (strUpper == strUpperField)
                                {
                                  ssEmail << m->first << ": " << m->second;
                                  if (strUpper == "CONTENT-TYPE")
                                  {
                                    for (list<map<string, string> >::iterator n = param.begin(); n != param.end(); n++)
                                    {
                                      for (map<string, string>::iterator o = n->begin(); o != n->end(); o++)
                                      {
                                        ssEmail << "; " << o->first << "=" << o->second;
                                      }
                                    }
                                  }
                                  ssEmail << endl;
                                }
                              }
                            }
                            ssBuffer << ssEmail.str().size() << "}\r\n" << ssEmail.str();
                          }
                          else if ((*k) == "TEXT")
                          {
                            ssBuffer << ((!bFirst)?" ":"") << "BODY[";
                            if (!deepformat.empty())
                            {
                              for (list<string>::iterator l = deepformat.begin(); l != deepformat.end(); l++)
                              {
                                if (l != deepformat.begin())
                                {
                                  ssBuffer << " ";
                                }
                                ssBuffer << (*l);
                              }
                              ssBuffer << "] {" << (strHeader.size() + strBody.size()) << "}\r\n";
                              ssBuffer << strHeader << strBody << "\r\n";
                            }
                            else
                            {
                              ssBuffer << (*k) << "]<0> {" << (strHeader.size() + strBody.size()) << "}\r\n";
                              ssBuffer << strHeader << strBody;
                            }
                          }
                        }
                      }
                      else
                      {
                        ssBuffer << ((!bFirst)?" ":"") << "BODY[] {" << (strHeader.size() + strBody.size()) << "}\r\n";
                        ssBuffer << strHeader << strBody;
                      }
                    }
                    else if ((*j) == "BODYSTRUCTURE")
                    {
                      string strDateTime;
                      ssBuffer << ((!bFirst)?" ":"") << (*j) << " (";
                      if (header.find("Content-Type") != header.end())
                      {
                        size_t nPosition;
                        string strSubType, strType;
                        if ((nPosition = header["Content-Type"].find("/")) != string::npos)
                        {
                          ssBuffer << "\"" << header["Content-Type"].substr(0, nPosition) << "\" ";
                          ssBuffer << "\"" << header["Content-Type"].substr(nPosition + 1, header["Content-Type"].size() - (nPosition + 1)) << "\" ";
                          if (!param.empty())
                          {
                            ssBuffer << "(";
                            for (list<map<string, string> >::iterator k = param.begin(); k != param.end(); k++)
                            {
                              if (k != param.begin())
                              {
                                ssBuffer << " ";
                              }
                              for (map<string, string>::iterator l = k->begin(); l != k->end(); l++)
                              {
                                string strFirst = l->first, strSecond = l->second;
                                if (!strFirst.empty() && strFirst[0] == '"')
                                {
                                  strFirst.erase(0, 1);
                                }
                                if (!strFirst.empty() && strFirst[strFirst.size() - 1] == '"')
                                {
                                  strFirst.erase(strFirst.size() - 1, 1);
                                }
                                if (!strSecond.empty() && strSecond[0] == '"')
                                {
                                  strSecond.erase(0, 1);
                                }
                                if (!strSecond.empty() && strSecond[strSecond.size() - 1] == '"')
                                {
                                  strSecond.erase(strSecond.size() - 1, 1);
                                }
                                ssBuffer << "\"" << strFirst << "\" \"" << strSecond << "\"";
                              }
                            }
                            ssBuffer << ") ";
                          }
                          else
                          {
                            ssBuffer << "NIL ";
                          }
                        }
                        else
                        {
                          ssBuffer << "NIL NIL NIL ";
                        }
                      }
                      else
                      {
                        ssBuffer << "NIL NIL NIL ";
                      }
                      ssBuffer << "NIL "; // body encoding
                      if (header.find("Content-Description") != header.end())
                      {
                        ssBuffer << "\"" << header["Content-Description"] << "\"";
                      }
                      else
                      {
                        ssBuffer << "NIL ";
                      }
                      ssBuffer << "\"7BIT\" "; // body encoding
                      ssBuffer << (strHeader.size() + strBody.size()); // body size
                      ssBuffer << ")";
                    }
                    else if ((*j) == "ENVELOPE")
                    {
                      string strDateTime, strValue;
                      ssBuffer << ((!bFirst)?" ":"") << (*j) << " (";
                      formatTime(message[i][((message[i].find("receivedTime") != message[i].end())?"receivedTime":"lastActionTime")], strDateTime);
                      ssBuffer << "\"" << strDateTime << "\" "; // date
                      ssBuffer << "\"" << manip.trim(strValue, message[i]["subject"]) << "\" "; // subject
                      ssBuffer << "((NIL NIL \"" << message[i]["fromAddress"] << "\" \"bm.addr\")) "; // from
                      ssBuffer << "((NIL NIL \"" << message[i]["fromAddress"] << "\" \"bm.addr\")) "; // sender
                      ssBuffer << "((NIL NIL \"" << message[i]["fromAddress"] << "\" \"bm.addr\")) "; // reply-to
                      ssBuffer << "((NIL NIL \"" << ((message[i]["toAddress"] == "Broadcast")?message[i]["fromAddress"]:message[i]["toAddress"]) << "\" \"bm.addr\")) "; // to
                      ssBuffer << "NIL "; // cc
                      ssBuffer << "NIL "; // bcc
                      ssBuffer << "NIL "; // in-replay-to
                      if (header.find("Message-ID") != header.end())
                      {
                        ssBuffer << "\"" << header["Message-ID"] << "\""; // message-id
                      }
                      else
                      {
                        ssBuffer << "\"\"";
                      }
                      ssBuffer << ")";
                    }
                    else if ((*j) == "FLAGS")
                    {
                      ssBuffer << ((!bFirst)?" ":"") << (*j) << " (\\Seen)";
                    }
                    else if ((*j) == "INTERNALDATE")
                    {
                      string strDateTime;
                      formatTime(message[i][((message[i].find("receivedTime") != message[i].end())?"receivedTime":"lastActionTime")], strDateTime);
                      ssBuffer << ((!bFirst)?" ":"") << (*j) << " \"" << strDateTime << "\"";
                    }
                    else if ((*j) == "RFC822.SIZE")
                    {
                      ssBuffer << ((!bFirst)?" ":"") << (*j) << " " << (strHeader.size() + strBody.size());
                    }
                    else if ((*j) == "UID" && strPreUpperCommand != "UID")
                    {
                      ssBuffer << ((!bFirst)?" ":"") << (*j) << " " << (i + 1);
                    }
                    if (bFirst)
                    {
                      bFirst = false;
                    }
                  }
                  ssBuffer << ")\r\n";
                  header.clear();
                  for (list<map<string, string> >::iterator j = param.begin(); j != param.end(); j++)
                  {
                    j->clear();
                  }
                  param.clear();
                }
              }
              if ((unPosition = strMessages.find(",")) != string::npos)
              {
                strRange = strMessages.substr(0, unPosition);
                strMessages.erase(0, unPosition + 1);
              }
              else
              {
                strRange = strMessages;
                strMessages.clear();
              }
            }
          }
          ssBuffer << strAction << " OK" << ((!strPreCommand.empty())?(string)" " + strPreCommand:"") << " " << strCommand << " completed\r\n";
          format.clear();
          subformat.clear();
          deepformat.clear();
          for (size_t i = 0; i < message.size(); i++)
          {
            message[i].clear();
          }
          message.clear();
        }
        // }}}
        // {{{ SEARCH
        else if (strUpperCommand == "SEARCH")
        {
          bool bAll = false, bSeen = false;
          string strFlag;
          while (ssData >> strFlag)
          {
            if (strFlag == "ALL")
            {
              bAll = true;
            }
            else if (strFlag == "NOT")
            {
              ssData >> strFlag;
              if (strFlag == "DELETED")
              {
                bAll = true;
                bSeen = true;
              }
            }
            else if (strFlag == "SEEN" || strFlag == "UNSEEN")
            {
              bSeen = true;
            }
          }
          ssBuffer << "* " << strCommand;
          if (bAll && bSeen)
          {
            string strError;
            vector<map<string, string> > message;
            if (((strSelectedMailBox == "INBOX" && gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError)) || (strSelectedMailBox == "SENT" && gConf[strAccount]->bitMessage.getAllSentMessages(strAccount, message, strError))) && !message.empty())
            {
              for (size_t i = 0; i < message.size(); i++)
              {
                ssBuffer << " " << (i + 1);
              }
            }
            for (size_t i = 0; i < message.size(); i++)
            {
              message[i].clear();
            }
            message.clear();
          }
          ssBuffer << "\r\n";
          ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
        }
        // }}}
        // {{{ APPEND
        else if (strUpperCommand == "APPEND")
        {
          ssize_t nLength = 0;
          string strLength;
          while (nLength == 0 && ssData >> strLength)
          {
            if (strLength.size() > 2 && strLength[0] == '{' && strLength[strLength.size() - 1] == '}')
            {
              nLength = atoi(strLength.substr(1, strLength.size() - 2).c_str());
            }
          }
          if (nLength > 0)
          {
            char szBuffer[1024];
            ssize_t nReturn;
            writeLine(ssl, strPrefix, "+\r\n");
            while (nLength > 0 && (nReturn = SSL_read(ssl, szBuffer, ((nLength < 1024)?nLength:1023))) > 0)
            {
              szBuffer[nReturn] = '\0';
              cout << szBuffer << flush;
              nLength -= nReturn;
            }
            if (nLength == 0)
            {
              char cChar;
              while (SSL_read(ssl, &cChar, 1) == 1 && cChar != '\n')
              {
                cout << cChar << flush;
              }
              ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
            }
            else
            {
              bExit = true;
              cerr << "IMAP ERROR:  Failed to read message from client." << endl;
            }
          }
          else
          {
            ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
          }
        }
        // }}}
        // {{{ CLOSE
        else if (strUpperCommand == "CLOSE")
        {
          gConf[strAccount]->bitMessage.trashMessages();
          ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
        }
        // }}}
        // {{{ EXPUNGE
        else if (strUpperCommand == "EXPUNGE")
        {
          string strError;
          vector<map<string, string> > message;
          if ((strSelectedMailBox == "INBOX" && gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError)) || (strSelectedMailBox == "SENT" && gConf[strAccount]->bitMessage.getAllSentMessages(strAccount, message, strError)))
          {
            list<string> trash;
            gConf[strAccount]->bitMessage.getTrashedMessages(trash);
            for (size_t i = 0; i < message.size(); i++)
            {
              for (list<string>::iterator j = trash.begin(); j != trash.end(); j++)
              {
                if (message[i]["msgid"] == (*j))
                {
                  ssBuffer << "* " << (i + 1) << " " << strCommand << "\r\n";
                }
              }
            }
            trash.clear();
            gConf[strAccount]->bitMessage.trashMessages();
            ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
          }
          else
          {
            stringstream ssSubData;
            ssBuffer << strAction << " NO " << strCommand << " failure (" << strError << ")\r\n";
          }
          for (size_t i = 0; i < message.size(); i++)
          {
            message[i].clear();
          }
          message.clear();
        }
        // }}}
        // {{{ STORE
        else if (strUpperCommand == "STORE")
        {
          bool bDeleted = false;
          size_t unPosition[2];
          list<string> flag;
          string strFlags, strMessages, strType, strUpperType;
          ssData >> strMessages >> strType;
          manip.toUpper(strUpperType, strType);
          utility.getLine(ssData, strFlags);
          if ((unPosition[0] = strFlags.find("(")) != string::npos && (unPosition[1] = strFlags.find(")", unPosition[0])) != string::npos)
          {
            string strFlag;
            stringstream ssFlags(strFlags.substr(unPosition[0] + 1, unPosition[1] - (unPosition[0] + 1)));
            while (ssFlags >> strFlag)
            {
              flag.push_back(strFlag);
            }
          }
          for (list<string>::iterator i = flag.begin(); i != flag.end(); i++)
          {
            if ((*i) == "\\Deleted")
            {
              bDeleted = true;
            }
          }
          if (flag.empty() || bDeleted)
          {
            list<string> trash;
            string strError;
            vector<map<string, string> > message;
            gConf[strAccount]->bitMessage.getTrashedMessages(trash);
            if ((strSelectedMailBox == "INBOX" && gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError)) || (strSelectedMailBox == "SENT" && gConf[strAccount]->bitMessage.getAllSentMessages(strAccount, message, strError)))
            {
              string strRange;
              if ((unPosition[0] = strMessages.find(",")) != string::npos)
              {
                strRange = strMessages.substr(0, unPosition[0]);
                strMessages.erase(0, unPosition[0] + 1);
              }
              else
              {
                strRange = strMessages;
                strMessages.clear();
              }
              while (!strRange.empty())
              {
                size_t unEnd, unStart;
                if ((unPosition[0] = strRange.find(":")) != string::npos)
                {
                  unStart = atoi(strRange.substr(0, unPosition[0]).c_str());
                  if (strRange.substr(unPosition[0] + 1, strRange.size() - (unPosition[0] + 1)) == "*")
                  {
                    unEnd = 0;
                  }
                  else
                  {
                    unEnd = atoi(strRange.substr(unPosition[0] + 1, strRange.size() - (unPosition[0] + 1)).c_str());
                  }
                }
                else
                {
                  unStart = unEnd = atoi(strRange.c_str());
                }
                for (size_t i = (unStart - 1); i < ((unEnd == 0)?message.size():unEnd); i++)
                {
                  if (i < message.size())
                  {
                    bool bFound = false;
                    if (bDeleted && (strUpperType == "FLAGS" || strUpperType == "FLAGS.SILENT" || strUpperType == "+FLAGS" || strUpperType == "+FLAGS.SILENT"))
                    {
                      for(list<string>::iterator j = trash.begin(); j != trash.end(); j++)
                      {
                        if (message[i]["msgid"] == (*j))
                        {
                          bFound = true;
                        }
                      }
                      if (!bFound)
                      {
                        gConf[strAccount]->bitMessage.trashMessage(message[i]["msgid"]);
                        ssBuffer << "* " << (i + 1) << " " << strCommand << " (FLAGS (\\Deleted))\r\n";
                      }
                    }
                    else
                    {
                      for(list<string>::iterator j = trash.begin(); j != trash.end(); j++)
                      {
                        if (message[i]["msgid"] == (*j))
                        {
                          bFound = true;
                        }
                      }
                      if (bFound)
                      {
                        gConf[strAccount]->bitMessage.untrashMessage(message[i]["msgid"]);
                        ssBuffer << "* " << (i + 1) << " " << strCommand << " (FLAGS ())\r\n";
                      }
                    }
                  }
                }
                if ((unPosition[0] = strMessages.find(",")) != string::npos)
                {
                  strRange = strMessages.substr(0, unPosition[0]);
                  strMessages.erase(0, unPosition[0] + 1);
                }
                else
                {
                  strRange = strMessages;
                  strMessages.clear();
                }
              }
              ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
            }
            else
            {
              ssBuffer << strAction << " NO " << strCommand << " failure (" << strError << ")\r\n";
            }
            for (size_t i = 0; i < message.size(); i++)
            {
              message[i].clear();
            }
            message.clear();
          }
          else
          {
            ssBuffer << strAction << " OK " << strCommand << " completed\r\n";
          }
          flag.clear();
          gConf[strAccount]->bitMessage.trashMessages();
        }
        // }}}
        else
        {
          ssBuffer << strAction << " BAD command unknown or arguments invalid\r\n";
        }
      }
      else
      {
        ssBuffer << strAction << " NO " << strCommand << " failure\r\n";
      }
      writeLine(ssl, strPrefix, ssBuffer.str());
    }
  }
  else
  {
    cerr << strPrefix << " write error:  " << strerror(errno) << endl;
  }
  fdSocket = SSL_get_fd(ssl);
  SSL_free(ssl);
  close(fdSocket);
}
// }}}
// {{{ readLine()
bool readLine(SSL *ssl, string &strBuffer, const string strPrefix, string &strLine)
{
  bool bExit = false, bResult = false;
  char szBuffer[4096];
  int nReturn;
  size_t unPosition;

  while (!bExit && !bResult)
  {
    if ((unPosition = strBuffer.find("\n")) != string::npos)
    {
      bResult = true;
      strLine = strBuffer.substr(0, unPosition);
      strBuffer.erase(0, unPosition + 1);
      cout << strPrefix << " IN:  " << strLine << endl;
    }
    else if ((nReturn = SSL_read(ssl, szBuffer, 4096)) > 0)
    {
      strBuffer.append(szBuffer, nReturn);
    }
    else
    {
      bExit = true;
    }
  }

  return bResult;
}
// }}}
// {{{ pop()
void pop(SSL *ssl)
{
  int fdSocket;
  string strBuffer, strError, strPrefix = "POP";
  stringstream ssPointer;
  Utility utility(strError);

  ssPointer << "[" << ssl << "]";
  strPrefix += ssPointer.str();
  if (writeLine(ssl, strPrefix, "+OK server ready\r\n"))
  {
    bool bAuthenticated = false, bExit = false;
    string strAccount, strLine, strPassword, strUser;
    while (!bExit && readLine(ssl, strBuffer, strPrefix, strLine))
    {
      string strCommand;
      stringstream ssBuffer, ssData;
      ssData.str(strLine);
      ssData >> strCommand;
      // {{{ USER
      if (strCommand == "USER")
      {
        ssData >> strUser;
        ssBuffer << "+OK user accepted\r\n";
      }
      // }}}
      // {{{ PASS
      else if (strCommand == "PASS")
      {
        ssData >> strPassword;
        if (authenticate("POP", strUser, strPassword, strAccount))
        {
          bAuthenticated = true;
          ssBuffer << "+OK pass accepted";
        }
        else
        {
          strPassword.clear();
          ssBuffer << "-ERR auth rejected";
        }
        ssBuffer << "\r\n";
      }
      // }}}
      // {{{ QUIT
      else if (strCommand == "QUIT")
      {
        bExit = true;
        ssBuffer << "+OK exiting\r\n";
        if (bAuthenticated)
        {
          gConf[strAccount]->bitMessage.trashMessages();
          bAuthenticated = false;
          strAccount.clear();
        }
      }
      // }}}
      // {{{ NOOP
      else if (strCommand == "NOOP")
      {
        ssBuffer << "+OK\r\n";
      }
      // }}}
      else if (bAuthenticated)
      {
        // {{{ STAT
        if (strCommand == "STAT")
        {
          size_t unSize = 0;
          string strError;
          vector<map<string, string> > message;
          if (gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError))
          {
            for (size_t i = 0; i < message.size(); i++)
            {
              if (message[i]["message"].find("Content-Type: ") == string::npos)
              {
                string strHeaders;
                unSize += buildHeaders(message[i], strHeaders).size();
              }
              unSize += message[i]["message"].size();
            }
            ssBuffer << "+OK " << message.size() << " " << unSize << "\r\n";
          }
          else
          {
            ssBuffer << "-ERR " << strError << "\r\n";
          }
          for (size_t i = 0; i < message.size(); i++)
          {
            message[i].clear();
          }
          message.clear();
        }
        // }}}
        // {{{ LIST
        else if (strCommand == "LIST")
        {
          size_t unSize = 0;
          string strError;
          stringstream ssSubData;
          vector<map<string, string> > message;
          if (gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError))
          {
            for (size_t i = 0; i < message.size(); i++)
            {
              ssSubData << (i + 1) << " ";
              if (message[i]["message"].find("Content-Type: ") != string::npos)
              {
                ssSubData << message[i]["message"].size();
              }
              else
              {
                string strHeaders;
                ssSubData << (buildHeaders(message[i], strHeaders).size() + message[i]["message"].size());
                unSize += buildHeaders(message[i], strHeaders).size();
              }
              ssSubData << "\r\n";
              unSize += message[i]["message"].size();
            }
            ssSubData << ".\r\n";
            ssBuffer << "+OK " << message.size() << " messages (" << unSize << " octets)\r\n";
            ssBuffer << ssSubData.str();
          }
          else
          {
            ssBuffer << "-ERR " << strError << "\r\n";
          }
          for (size_t i = 0; i < message.size(); i++)
          {
            message[i].clear();
          }
          message.clear();
        }
        // }}}
        // {{{ TOP
        else if (strCommand == "TOP")
        {
          size_t unLines, unMsgID;
          string strError;
          vector<map<string, string> > message;
          ssData >> unMsgID >> unLines;
          unMsgID--;
          if (gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError))
          {
            if (unMsgID < message.size())
            {
              string strLine;
              stringstream ssBody;
              if (message[unMsgID]["message"].find("Content-Type: ") == string::npos)
              {
                string strHeaders;
                ssBody << buildHeaders(message[unMsgID], strHeaders);
              }
              ssBody << message[unMsgID]["message"];
              ssBuffer << "+OK top of message follows\r\n";
              for (size_t i = 0; utility.getLine(ssBody, strLine) && i < unLines; i++)
              {
                ssBuffer << strLine << endl;
              }
            }
            else
            {
              ssBuffer << "-ERR Message " << unMsgID << " does not exist.\r\n";
            }
          }
          else
          {
            ssBuffer << "-ERR " << strError << "\r\n";
          }
          for (size_t i = 0; i < message.size(); i++)
          {
            message[i].clear();
          }
          message.clear();
        }
        // }}}
        // {{{ RETR
        else if (strCommand == "RETR")
        {
          size_t unMsgID;
          string strError;
          vector<map<string, string> > message;
          ssData >> unMsgID;
          unMsgID--;
          if (gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError))
          {
            if (unMsgID < message.size())
            {
              if (message[unMsgID]["message"].find("Content-Type: ") != string::npos)
              {
                ssBuffer << "+OK " << message[unMsgID]["message"].size() << " octets\r\n";
                ssBuffer << message[unMsgID]["message"];
              }
              else
              {
                string strHeaders;
                ssBuffer << "+OK " << (buildHeaders(message[unMsgID], strHeaders).size() + message[unMsgID]["message"].size()) << " octets\r\n";
                ssBuffer << strHeaders << message[unMsgID]["message"];
              }
              ssBuffer << "\r\n.\r\n";
            }
            else
            {
              ssBuffer << "-ERR Message " << unMsgID << " does not exist.\r\n";
            }
          }
          else
          {
            ssBuffer << "-ERR " << strError << "\r\n";
          }
          for (size_t i = 0; i < message.size(); i++)
          {
            message[i].clear();
          }
          message.clear();
        }
        // }}}
        // {{{ DELE
        else if (strCommand == "DELE")
        {
          size_t unMsgID;
          string strError;
          vector<map<string, string> > message;
          ssData >> unMsgID;
          unMsgID--;
          if (gConf[strAccount]->bitMessage.getAllInboxMessages(strAccount, message, strError))
          {
            if (unMsgID < message.size())
            {
              gConf[strAccount]->bitMessage.trashMessage(message[unMsgID]["msgid"]);
              ssBuffer << "+OK message deleted\r\n";
            }
            else
            {
              ssBuffer << "-ERR Message " << unMsgID << " does not exist.\r\n";
            }
          }
          else
          {
            ssBuffer << "-ERR " << strError << "\r\n";
          }
          for (size_t i = 0; i < message.size(); i++)
          {
            message[i].clear();
          }
          message.clear();
        }
        // }}}
        else
        {
          ssBuffer << "-ERR invalid request\r\n";
        }
      }
      else
      {
        ssBuffer << "-ERR invalid request\r\n";
      }
      writeLine(ssl, strPrefix, ssBuffer.str());
    }
  }
  else
  {
    cerr << strPrefix << " write error:  " << strerror(errno) << endl;
  }
  fdSocket = SSL_get_fd(ssl);
  SSL_free(ssl);
  close(fdSocket);
}
// }}}
// {{{ smtp()
void smtp(SSL *ssl)
{
  int fdSocket;
  string strBuffer, strError, strPrefix = "SMTP";
  stringstream ssPointer;
  StringManip manip;
  Utility utility(strError);

  ssPointer << "[" << ssl << "]";
  strPrefix += ssPointer.str();
  if (writeLine(ssl, strPrefix, "220 bm.addr ESMTP BitMail\r\n"))
  {
    bool bAuthenticated = false, bExit = false, bInData = false;
    string strAccount, strFrom, strLine, strPassword, strPrevLine, strUser;
    list<string> data;
    while (!bExit && readLine(ssl, strBuffer, strPrefix, strLine))
    {
      // {{{ In DATA
      if (bInData)
      {
        if (strLine.size() == 2 && strLine[0] == '.' && strLine[1] == '\r' && strPrevLine.size() >= 1 && strPrevLine[strPrevLine.size() - 1] == '\r')
        {
          bool bNewLine = false, bBoth = false, bSent = false;
          size_t nPosition;
          string strError;
          stringstream ssEmail;
          bInData = false;
          for (list<string>::iterator i = data.begin(); i != data.end(); i++)
          {
            ssEmail << (*i) << endl;
          }
          if ((nPosition = ssEmail.str().find("\n\n")) != string::npos)
          {
            bNewLine = true;
          }
          else if ((nPosition = ssEmail.str().find("\r\n\r\n")) != string::npos)
          {
            bBoth = true;
          }
          if (bNewLine || bBoth)
          {
            list<string> all;
            string strEmail, strFrom, strSubject;
            stringstream ssHeader(ssEmail.str().substr(0, nPosition));
            strEmail = ssEmail.str().substr(nPosition + ((bNewLine)?2:4), ssEmail.str().size() - (nPosition + ((bNewLine)?2:4)));
            while (utility.getLine(ssHeader, strLine))
            {
              bool bConcat = false, bTest = true;
              string strConcat, strRemainder, strTest, strType;
              stringstream ssLine;
              strTest = strLine;
              while (bTest)
              {
                bTest = false;
                while (!strTest.empty() && strTest[strTest.size() - 1] == '\r')
                {
                  strTest.erase(strTest.size() - 1);
                }
                while (!strTest.empty() && strTest[strTest.size() - 1] == ' ')
                {
                  strTest.erase(strTest.size() - 1);
                }
                strConcat += strTest;
                if (!strTest.empty() && strTest[strTest.size() - 1] == ',')
                {
                  bConcat = true;
                  bTest = true;
                  utility.getLine(ssHeader, strTest);
                }
              }
              if (bConcat)
              {
                strLine = strConcat;
              }
              ssLine.str(strLine);
              ssLine >> strType;
              ssLine.str(strLine.substr(strType.size() + 1, strLine.size() - (strType.size() + 1)));
              utility.getLine(ssLine, strRemainder);
              if (strType == "From:" || strType == "To:" || strType == "Cc:" || strType == "Bcc:")
              {
                string strToken;
                for (int i = 1; !manip.getToken(strToken, strRemainder, i, ",", true).empty(); i++)
                {
                  if ((nPosition = strToken.find("<")) != string::npos)
                  {
                    strToken.erase(0, nPosition + 1);
                  }
                  if ((nPosition = strToken.find(">")) != string::npos)
                  {
                    strToken.erase(nPosition, strToken.size() - nPosition);
                  }
                  if ((nPosition = strToken.find("@")) != string::npos)
                  {
                    strToken.erase(nPosition, strToken.size() - nPosition);
                  }
                  if (strType == "From:")
                  {
                    strFrom = strToken;
                  }
                  else if (strType == "To:" || strType == "Cc:" || strType == "Bcc:")
                  {
                    all.push_back(strToken);
                  }
                }
              }
              else if (strType == "Subject:")
              {
                strSubject = strRemainder;
              }
            }
            all.sort();
            all.unique();
            if (!all.empty())
            {
              for (list<string>::iterator i = all.begin(); i != all.end(); i++)
              {
                if (((*i) == "Broadcast")?gConf[strAccount]->bitMessage.sendBroadcast(strFrom, strSubject, ssEmail.str(), strError):gConf[strAccount]->bitMessage.sendMessage((*i), strFrom, strSubject, ssEmail.str(), strError))
                {
                  bSent = true;
                }
              }
            }
            else
            {
              strError = "No recipient provided.";
            }
            all.clear();
          }
          else
          {
            strError = "No recipient provided.";
          }
          data.clear();
          if (bSent)
          {
            writeLine(ssl, strPrefix, "250 OK queued\r\n");
          }
          else
          {
            writeLine(ssl, strPrefix, (string)"-ERR " + strError + (string)"\r\n");
          }
        }
        else
        {
          data.push_back(strLine);
          strPrevLine = strLine;
        }
      }
      // }}}
      else
      {
        string strCommand;
        stringstream ssData;
        ssData.str(strLine);
        ssData >> strCommand;
        // {{{ EHLO or HELO or MAIL or RCPT
        if (strCommand == "EHLO" || strCommand == "HELO" || strCommand == "MAIL" || strCommand == "RCPT")
        {
          if (strCommand == "EHLO")
          {
            writeLine(ssl, strPrefix, "250-OK\r\n");
            writeLine(ssl, strPrefix, "250 AUTH LOGIN PLAIN\r\n");
          }
          else
          {
            writeLine(ssl, strPrefix, "250 OK\r\n");
          }
        }
        // }}}
        // {{{ AUTH
        else if (strCommand == "AUTH")
        {
          string strExtra, strType;
          ssData >> strType >> strExtra;
          // {{{ LOGIN
          if (strType == "LOGIN")
          {
            string strPrompt, strUser, strPassword;
            gBitMessage.encodeBase64("Username:", strPrompt);
            strPrompt = (string)"334 " + strPrompt + (string)"\r\n";
            writeLine(ssl, strPrefix, strPrompt);
            readLine(ssl, strBuffer, strPrefix, strLine);
            ssData.str(strLine);
            ssData >> strLine;
            gBitMessage.decodeBase64(strLine, strUser);
            gBitMessage.encodeBase64("Password:", strPrompt);
            strPrompt = (string)"334 " + strPrompt + (string)"\r\n";
            writeLine(ssl, strPrefix, strPrompt);
            readLine(ssl, strBuffer, strPrefix, strLine);
            ssData.str(strLine);
            ssData >> strLine;
            gBitMessage.decodeBase64(strLine, strPassword);
            if (authenticate("SMTP", strUser, strPassword, strAccount))
            {
              bAuthenticated = true;
              writeLine(ssl, strPrefix, "235 Authentication successful\r\n");
            }
            else
            {
              writeLine(ssl, strPrefix, "535 Authentication rejected\r\n");
            }
          }
          // }}}
          // {{{ PLAIN
          else if (strType == "PLAIN")
          {
            string strAuth;
            if (strExtra.empty())
            {
              writeLine(ssl, strPrefix, "334\r\n");
              readLine(ssl, strBuffer, strPrefix, strLine);
              ssData.str(strLine);
              ssData >> strLine;
            }
            else
            {
              strLine = strExtra;
            }
            gBitMessage.decodeBase64(strLine, strAuth);
            if (!strAuth.empty() && strAuth[0] == '\0')
            {
              size_t unPosition;
              if ((unPosition = strAuth.find('\0', 1)) != string::npos)
              {
                string strUser = strAuth.substr(1, unPosition - 1), strPassword = strAuth.substr(unPosition + 1, strAuth.size() - (unPosition + 1));
                if (authenticate("SMTP", strUser, strPassword, strAccount))
                {
                  bAuthenticated = true;
                  writeLine(ssl, strPrefix, "235 Authentication successful\r\n");
                }
                else
                {
                  writeLine(ssl, strPrefix, "535 Authentication rejected\r\n");
                }
              }
              else
              {
                writeLine(ssl, strPrefix, "535 Authentication rejected\r\n");
              }
            }
            else
            {
              writeLine(ssl, strPrefix, "535 Authentication rejected\r\n");
            }
          }
          // }}}
          else
          {
            writeLine(ssl, strPrefix, "535 Invalid authorization type.\r\n");
          }
        }
        // }}}
        // {{{ DATA
        else if (strCommand == "DATA")
        {
          if (bAuthenticated)
          {
            bInData = true;
            writeLine(ssl, strPrefix, "354 End data with <CR><LF>.<CR><LF>\r\n");
          }
          else
          {
            writeLine(ssl, strPrefix, "535 Not Authorized\r\n");
          }
        }
        // }}}
        // {{{ QUIT
        else if (strCommand == "QUIT")
        {
          bExit = true;
          writeLine(ssl, strPrefix, "221 Bye\r\n");
        }
        // }}}
      }
    }
  }
  else
  {
    cerr << strPrefix << " write error:  " << strerror(errno) << endl;
  }
  fdSocket = SSL_get_fd(ssl);
  SSL_free(ssl);
  close(fdSocket);
}
// }}}
// {{{ writeLine()
bool writeLine(SSL *ssl, const string strPrefix, string strLine)
{
  ssize_t unReturn;
  string strBuffer, strError;
  stringstream ssBuffer(strLine);
  Utility utility(strError);

  while (utility.getLine(ssBuffer, strBuffer))
  {
    cout << strPrefix << " OUT: " << strBuffer << endl;
  }
  strBuffer = strLine;
  while (!strBuffer.empty() && (unReturn = SSL_write(ssl, strBuffer.c_str(), strBuffer.size())) > 0)
  {
    strBuffer.erase(0, unReturn);
  }

  return strBuffer.empty();
}
// }}}
