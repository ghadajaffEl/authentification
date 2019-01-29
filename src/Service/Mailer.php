<?php
/**
 * Created by PhpStorm.
 * User: sarfaoui
 * Date: 07/01/2019
 * Time: 09:01
 */

namespace App\Service;

class Mailer
{
    private $mailer;

    private $twig;

    private $mailFrom;

    public function __construct(\Swift_Mailer $mailer, \Twig_Environment $twig, string $mailFrom)
    {
        $this->mailer = $mailer;
        $this->twig = $twig;
        $this->mailFrom = $mailFrom;
    }

    /**
     * @param $body
     */
    public function sendMail($email, $subject, $body)
    {
        $message = new \Swift_Message();
        $message->setSubject($subject)
            ->setFrom($this->mailFrom)
            ->setTo($email)
            ->setBody($body, 'text/html');
        $this->mailer->send($message);
    }

}