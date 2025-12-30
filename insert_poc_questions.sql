-- Perguntas de PoC para BlackDomain (Bloqueia o unlock imediato)

DELETE FROM public.challenge_poc_questions WHERE challenge_id = 'blackdomain';

INSERT INTO public.challenge_poc_questions (
    challenge_id,
    question_order,
    question_text,
    question_text_pt,
    validation_type,
    correct_answer,
    points
) VALUES 
(
    'blackdomain',
    1,
    'Which TCP port is typically used by SMB?',
    'Qual porta TCP é tipicamente utilizada pelo SMB?',
    'exact',
    '445',
    10
),
(
    'blackdomain',
    2,
    'What is the domain name configured in the environment?',
    'Qual o nome do domínio configurado no ambiente?',
    'exact',
    'blackdomain.local',
    10
),
(
    'blackdomain',
    3,
    'Which TCP port is used by the Kerberos service?',
    'Qual porta TCP é utilizada pelo serviço Kerberos?',
    'exact',
    '88',
    10
);
