using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Configuration;

namespace AuthServer
{
    public class authDbUtility
    {
        public static int ValidateUser(string uname, string pword, string account)
        {
            MySqlConnection scon = new MySqlConnection(WebConfigurationManager.ConnectionStrings["LocalMySqlServer"].ConnectionString);
            MySqlCommand scmd = new MySqlCommand();
            scon.Open();
            scmd.Connection = scon;
            int ret = 0;
            try
            {
                scmd.CommandText = "SELECT count(a.uid) as ucount FROM users a INNER JOIN accounts b ON a.accid=b.accid WHERE b.acc=@acc AND a.uname=@uname AND a.pword=@pword";
                scmd.Parameters.AddWithValue("uname", uname);
                scmd.Parameters.AddWithValue("pword", pword);
                scmd.Parameters.AddWithValue("acc", account);
                scmd.Prepare();
                ret = Convert.ToInt32(scmd.ExecuteScalar());
            }
            catch (Exception ee)
            {
                ret = 0;
            }
            finally
            {
                if (scmd != null)
                    scmd.Dispose();
                if (scon.State == ConnectionState.Open)
                {
                    scon.Dispose();
                    scon.Close();
                }
            }
            return ret;
        }

        public static List<string> GetRolesForUser(int uid)
        {
            MySqlConnection scon = new MySqlConnection(WebConfigurationManager.ConnectionStrings["LocalMySqlServer"].ConnectionString);
            MySqlCommand scmd = new MySqlCommand();
            scon.Open();
            scmd.Connection = scon;
            List<string> roleList = new List<string>();
            try
            {
                scmd.CommandText = "SELECT a.role FROM roles a INNER JOIN userroles b ON a.rid=b.rid WHERE b.uid=@uid";
                scmd.Parameters.AddWithValue("uid", uid);
                scmd.Prepare();
                MySqlDataReader sdr = scmd.ExecuteReader();
                if (sdr.HasRows)
                {
                    while (sdr.Read())
                    {
                        roleList.Add(sdr.GetString(0));
                    }
                }
                sdr.Close();
                sdr.Dispose();

            }
            catch (Exception ee)
            {
                roleList = null;
            }
            finally
            {
                if (scmd != null)
                    scmd.Dispose();
                if (scon.State == ConnectionState.Open)
                {
                    scon.Dispose();
                    scon.Close();
                }
            }
            return roleList;
        }
    }
}