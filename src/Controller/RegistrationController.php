<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Service\Uploader;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Contracts\Translation\TranslatorInterface;

class RegistrationController extends AbstractController
{
    #[Route('/register', name: 'app_register')]
    public function register(Uploader $uploader, Request $request, UserPasswordHasherInterface $userPasswordHasher, EntityManagerInterface $entityManager, MailerInterface $mailer): Response
    {
        $user = new User();
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $picture = $form->get('pictureFile')->getData();
            $user->setPicture($uploader->uploadProfileImage($picture));
            $hash = $userPasswordHasher->hashPassword($user, $user->getPassword());
            $user->setPassword($hash);

            $entityManager->persist($user);
            $entityManager->flush();

            $email = (new TemplatedEmail())
                ->to('ryan@example.com')
                ->subject('Thanks for signing up!')

                // path of the Twig template to render
                ->htmlTemplate('@email_templates/welcome.html.twig')

                // pass variables (name => value) to the template
                ->context([
                    'username' => $user->getFirstname(),
                ])
            ;
            try {
                $mailer->send($email);
            } catch (TransportExceptionInterface $e) {
            }

            return $this->redirectToRoute('app_home');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form->createView(),
        ]);
    }
}
