import nodemailer from 'nodemailer';
export async function sendMail(to: string, subject: string, html: string) { 
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) { 
        console.log('Email environments are not available!');
        return;
    }

    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT || "587");
    const user = process.env.SMTP_USER;

    const pass = process.env.SMTP_PASS;

    const from = process.env.EMAIL_FROM;

    var transport = nodemailer.createTransport({
        host,
        port,
        auth: {
            user,
            pass,
        },
    });

    transport.sendMail(
      {
        from,
        to: to || "A Test User <to@example.com>",
        subject: subject || "Hello from Mailtrap",
        text: html || "This is a test e-mail message.",
      },
      (error, info) => {
        if (error) {
          return console.log(error);
        }
        console.log("Message sent: %s", info.messageId);
      },
    );
}
