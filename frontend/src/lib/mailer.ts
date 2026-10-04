import nodemailer from 'nodemailer';

const gmailUser = process.env.GMAIL_USER;
const gmailPass = process.env.GMAIL_APP_PASSWORD;

// Create transporter — Gmail with App Password
export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: gmailUser,
    pass: gmailPass,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

export interface SendEmailOptions {
  from: { name: string; email: string };
  to: { name?: string; email: string }[];
  cc?: { name?: string; email: string }[];
  subject: string;
  body: string;
  replyTo?: string;
}

/**
 * Send a real email via Gmail SMTP
 */
export async function sendEmail(opts: SendEmailOptions): Promise<{ success: boolean; error?: string; messageId?: string }> {
  if (!gmailUser || !gmailPass) {
    console.warn('[Mailer] Gmail credentials not configured — email not sent externally');
    return { success: true, messageId: `mock-${Date.now()}` };
  }

  try {
    const info = await transporter.sendMail({
      from: `"${opts.from.name}" <${gmailUser}>`,
      replyTo: opts.from.email,
      to: opts.to.map(t => t.name ? `"${t.name}" <${t.email}>` : t.email).join(', '),
      cc: opts.cc?.map(c => c.name ? `"${c.name}" <${c.email}>` : c.email).join(', '),
      subject: opts.subject,
      text: opts.body,
      html: `<div style="font-family: Inter, system-ui, sans-serif; font-size: 14px; line-height: 1.6; color: #333; max-width: 640px; margin: 0 auto;">
        <div style="border-bottom: 1px solid #eee; padding-bottom: 16px; margin-bottom: 16px;">
          <img src="${process.env.APP_URL}/logo.png" alt="Garuda Mail" style="height: 28px;" onerror="this.style.display='none'" />
          <span style="font-weight: 700; color: #0ea5e9; margin-left: 8px;">GARUDA MAIL</span>
        </div>
        <pre style="white-space: pre-wrap; font-family: inherit; font-size: 14px; color: #444;">${opts.body}</pre>
        <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #eee; font-size: 11px; color: #999;">
          Sent via Garuda Mail — AI-Assisted Email Security Platform
        </div>
      </div>`,
    });

    return { success: true, messageId: info.messageId };
  } catch (error: any) {
    console.error('[Mailer] Send failed:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Verify SMTP connection
 */
export async function verifyConnection(): Promise<boolean> {
  if (!gmailUser || !gmailPass) return false;
  try {
    await transporter.verify();
    return true;
  } catch {
    return false;
  }
}
