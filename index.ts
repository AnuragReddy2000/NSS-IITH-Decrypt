import {google} from 'googleapis';
import Crypto from './CryptoUtils';

const SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/datastore'
]
const sheets = google.sheets('v4');
const googleAuth = google.auth;
const firestore = google.firestore('v1');

let getAuthToken = async () => {
    const auth = new googleAuth.GoogleAuth({
        scopes: SCOPES,
        keyFile: "./service_creds.json",
        projectId: "nss-iith-app",
    });
    const authToken = await auth.getClient();
    return authToken;
}

let getSpreadSheet = async (spreadsheetId : string, sheetName: string, auth:any) => {
    const res = await sheets.spreadsheets.values.get({
        spreadsheetId,
        auth,
        range: sheetName,
        majorDimension: "ROWS"
    });
    return res;
}

let getTimeInSec = (timestamp: string, monthFirst = false) => {
    timestamp = timestamp.replace(",","")
    const [date, time] = timestamp.split(" ")
    const date_components = date.split("/")
    const time_components = time.split(":")
    if (monthFirst){
        return new Date(Number(date_components[2]), 
            Number(date_components[0]), 
            Number(date_components[1]),
            Number(time_components[0]),
            Number(time_components[1]),
            Number(time_components[2])).getTime()
    }
    return new Date(Number(date_components[2]), 
            Number(date_components[1]), 
            Number(date_components[0]),
            Number(time_components[0]),
            Number(time_components[1]),
            Number(time_components[2])).getTime()
}

let verifyAttendance = async (sheetId: string, event_key: string, tolerance: Number, auth_token:any) => {
    const resp = await getSpreadSheet(sheetId, "Form Responses 1", auth_token)
    let newValues = resp.data.values
    let sign_col = 3
    let fail_count = 0
    let cipher = new Crypto(event_key);
    if (newValues != null){
        for (const row of newValues){
            if (row[0] == "Timestamp"){
                row.forEach((value, index) => {
                    if (value == "Signature"){
                        sign_col = index
                    }
                })
                row.push("Decrypted timestamp")
                row.push("Timing verification")
            }
            else{
                const dec_ts = await cipher.decrypt(row[sign_col]);
                row.push(dec_ts)
                if (dec_ts != "Illegal action! Key mismatch!"){
                    const time_diff = (getTimeInSec(row[0], true) - getTimeInSec(dec_ts))/1000
                    if (time_diff > tolerance){
                        row.push("FAIL")
                        fail_count += 1
                    }
                    else{
                        row.push("PASS")
                    }
                }
                else{
                    row.push("FAIL")
                    fail_count += 1
                }
            }
        }
        sheets.spreadsheets.values.update({
            spreadsheetId: sheetId,
            auth: auth_token,
            range: resp.data.range ? resp.data.range : "Form Response 1",
            valueInputOption: "RAW",
            requestBody: {
                range: resp.data.range,
                majorDimension: "ROWS",
                values: newValues
            }
        })
        return "Successfully Finished! Total verification fails: "  + fail_count.toString() 
    }
    else{
        return "Aborting! Empty sheet!!"
    }
}

let getEventKey = async (eventId: string, auth_token: any) => {
    const resp = await firestore.projects.databases.documents.get({
        auth: auth_token,
        name: "projects/nss-iith-app/databases/(default)/documents/event_records/events",
    });
    let eventKey = null
    if (resp.data.fields != null){
        resp.data.fields["details"].arrayValue?.values?.forEach((each: any) => {
            if (each.mapValue?.fields != null){
                if (each.mapValue?.fields["eventId"].stringValue == eventId){
                    eventKey =  each.mapValue?.fields["eventkey"].stringValue
                }
            } 
        })
    }
    return eventKey
}

let main = async () => {
    let sheetUrl = process.argv[2]
    let eventId  = process.argv[3]
    let tolerance = process.argv[4]
    const auth_token = await getAuthToken();
    const eventkey = await getEventKey(eventId, auth_token);
    if (eventkey != null){
        const outputMsg = await verifyAttendance(sheetUrl, eventkey, Number(tolerance), auth_token);
        console.log(outputMsg);
    }
    else{
        console.log("Illegal action! Invalid key!!");
    }
}

main();