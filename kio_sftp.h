/*
 * Copyright (c) 2001      Lucas Fisher <ljfisher@purdue.edu>
 * Copyright (c) 2009      Andreas Schneider <mail@cynapses.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License (LGPL) as published by the Free Software Foundation;
 * either version 2 of the License, or (at your option) any later
 * version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef __kio_sftp_h__
#define __kio_sftp_h__

#include <kurl.h>
#include <kio/global.h>
#include <kio/slavebase.h>
#include <kdebug.h>
#include <stdint.h>

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <libssh/callbacks.h>

// How big should each data packet be? Definitely not bigger than 64kb or
// you will overflow the 2 byte size variable in a sftp packet.
#define MAX_XFER_BUF_SIZE 60 * 1024
#define KIO_SFTP_DB 7120

namespace KIO {
  class AuthInfo;
}

class sftpProtocol : public KIO::SlaveBase
{

public:
  sftpProtocol(const QCString &pool_socket, const QCString &app_socket);
  virtual ~sftpProtocol();
  virtual void setHost(const QString& h, int port, const QString& user, const QString& pass) override;
  virtual void get(const KURL& url) override;
  virtual void listDir(const KURL& url)  override;
  virtual void mimetype(const KURL& url) override;
  virtual void stat(const KURL& url) override;
  virtual void put(const KURL& url, int permissions, bool overwrite, bool resume) override;
  virtual void copy(const KURL &src, const KURL &dest, int permissions, bool overwrite) override;
  virtual void closeConnection() override;
  virtual void slave_status() override;
  virtual void del(const KURL &url, bool isfile) override;
  virtual void chmod(const KURL& url, int permissions) override;
  virtual void symlink(const QString& target, const KURL& dest, bool overwrite) override;
  virtual void rename(const KURL& src, const KURL& dest, bool overwrite) override;
  virtual void mkdir(const KURL& url, int permissions) override;
  virtual void openConnection() override;

  // libssh authentication callback (note that this is called by the
  // global ::auth_callback() call.
  int auth_callback(const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata);

  // libssh logging callback (note that this is called by the
  // global ::log_callback() call.
  void log_callback(ssh_session session, int priority, const char *message,
    void *userdata);

private: // Private variables
  void statMime(const KURL &url);
  void closeFile();
  /** True if ioslave is connected to sftp server. */
  bool mConnected;

  /** Host we are connected to. */
  QString mHost;

  /** Port we are connected to. */
  int mPort;

  /** The ssh session for the connection */
  ssh_session mSession;

  /** The sftp session for the connection */
  sftp_session mSftp;

  /** Username to use when connecting */
  QString mUsername;

  /** User's password */
  QString mPassword;

  /** The open file */
  sftp_file mOpenFile;

  /** The open URL */
  KURL mOpenUrl;

  ssh_callbacks mCallbacks;

  /** Version of the sftp protocol we are using. */
  int sftpVersion;

  //struct Status
  //{
  //  int code;
  //  KIO::filesize_t size;
  //  QString text;
  //};

private: // private methods

  int authenticateKeyboardInteractive(KIO::AuthInfo &info);

  void reportError(const KURL &url, const int err);

  bool createUDSEntry(const QString &filename, const QByteArray &path,
      KIO::UDSEntry &entry, short int details);

  QString canonicalizePath(const QString &path);
};

#endif
