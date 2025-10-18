# Insecure direct object references — Apprentice

**Status:** Solved

---

## Goal

Find and exploit an IDOR vulnerability to access another user's data. The target is to find Carlos's chat transcript and retrieve his password.

---

## Steps (simple & complete)

1. **Explore the application**
   - Click on "Live chat" feature
   - Have a quick chat conversation with the support bot
   - Notice there's a "View transcript" button after the chat

2. **Analyze the transcript request**
   - Click "View transcript" and check the request:
```
   GET /download-transcript/2.txt
```
   - The number `2.txt` looks like it's sequentially assigned to chat sessions
   - This is a classic IDOR pattern - predictable resource identifiers

3. **Test for IDOR**
   - If your transcript is `2.txt`, try accessing `1.txt`:
```bash
   curl -s "https://TARGET/download-transcript/1.txt"
```
   - You should see another user's chat transcript!

4. **Find Carlos's transcript**
   - Keep trying different numbers until you find Carlos's chat:
```bash
   curl -s "https://TARGET/download-transcript/1.txt"
```
   - Look through the transcript for any sensitive information

5. **Extract the password**
   - In Carlos's chat, he mentions his password to the support agent
   - Copy that password from the transcript

6. **Submit the solution**
   - The lab typically solves automatically once you access Carlos's transcript
   - Or you might need to submit the password you found

---

## Example

- Vulnerable endpoint: `GET /download-transcript/2.txt`
- IDOR payload:
```bash
curl -s "https://TARGET/download-transcript/1.txt"
```
- Look for Carlos's password in the response

---

## Why this works

The application generates predictable file names (`1.txt`, `2.txt`, etc.) without checking if the requesting user actually owns that chat session. Anyone can guess these sequential IDs and access other users' private conversations.

---

**Lab 1 Complete ✓**